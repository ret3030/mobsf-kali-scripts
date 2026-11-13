#!/usr/bin/env bash
# dynamic-scan.sh: dynamic recon of an APK on a rooted API 30 emulator.
# Boots the emulator, installs a proxy CA via tmpfs (no writable /system needed), runs frida
# SSL-unpinning, routes traffic through mitmproxy, then collects and summarizes:
#   - cleartext HTTP and intercepted HTTPS
#   - secrets left in app storage and logcat
#   - exported component behaviour
# This is recon, not proof: review every finding by hand. Run as a normal user.
#
# Two modes:
#   scripts/dynamic-scan.sh app.apk [capture_seconds]   automated: launch, light interaction, collect
#   scripts/dynamic-scan.sh app.apk interactive         opens the emulator window and mitmweb, then
#                                                        waits while you log in and drive the app
#                                                        (your phase 3); Ctrl+C to stop and summarize.
# Must be executed, not sourced: with set -e a sourced exit would close your shell.
(return 0 2>/dev/null) && { echo "Run it, don't source it:  bash $0 <args>" >&2; return 1; }
set -euo pipefail

[ "$(id -u)" -ne 0 ] || { echo "Run as a normal user, not root."; exit 1; }
APK="${1:-}"
MODE="auto"; CAPTURE="${2:-90}"
[ "${2:-}" = "interactive" ] && MODE="interactive"
[ -n "$APK" ] && [ -f "$APK" ] || { echo "Usage: $0 path/to/app.apk [capture_seconds|interactive]"; exit 1; }

HERE="$(cd "$(dirname "$0")" && pwd)"
SDK="$HOME/Android/Sdk"
AVD="mobsf-api30"
API=30
IMAGE="system-images;android-$API;google_apis;x86_64"
SERIAL="emulator-5554"
FRIDA_VER="$(cd "$HOME/tools/MobSF" && python3 -m poetry run frida --version 2>/dev/null | tr -d '\r')"
PROXY_PORT=8080
HOST_FROM_GUEST="10.0.2.2"
A="$SDK/platform-tools/adb"
E="$SDK/emulator/emulator"
FRIDA="cd $HOME/tools/MobSF && python3 -m poetry run"

OUT="$HOME/mobsf-out/dyn-$(basename "$APK" .apk)-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUT"
adb() { "$A" -s "$SERIAL" "$@"; }

# 'adb root' restarts adbd, so the connection drops for a moment right after boot. Retry until
# the daemon is back as root instead of letting a transient "closed" abort the run.
adb_root() {
  for _ in $(seq 1 15); do
    case "$(adb root 2>&1)" in
      *"restarting adbd as root"*|*"already running as root"*)
        adb wait-for-device; sleep 1
        [ "$(adb shell id -u 2>/dev/null | tr -d '\r')" = 0 ] && return 0 ;;
    esac
    sleep 2
  done
  echo "Could not get root adb on the emulator"; return 1
}

# --- Preconditions -------------------------------------------------------
[ -r /dev/kvm ] && [ -w /dev/kvm ] || { echo "No /dev/kvm access, see mobsf-doctor.sh"; exit 1; }
[ -n "$FRIDA_VER" ] || { echo "frida not found in MobSF poetry env"; exit 1; }
command -v mitmdump >/dev/null || { echo "mitmdump missing: sudo apt install mitmproxy"; exit 1; }

# The API 30 AVD must exist (setup-mobsf.sh creates it; create it here if missing).
if [ ! -f "$HOME/.android/avd/$AVD.avd/config.ini" ]; then
  echo "[*] Creating $AVD (Android $API)"
  export ANDROID_SDK_ROOT="$SDK" ANDROID_HOME="$SDK"
  yes | "$SDK/cmdline-tools/latest/bin/sdkmanager" "$IMAGE" >/dev/null
  echo no | "$SDK/cmdline-tools/latest/bin/avdmanager" create avd -f -n "$AVD" -d pixel_5 -k "$IMAGE"
fi

# --- frida-server matching the client version ----------------------------
FS="$HOME/tools/frida-server-$FRIDA_VER-x86_64"
if [ ! -f "$FS" ]; then
  echo "[*] Downloading frida-server $FRIDA_VER"
  curl -fsSL -o "$FS.xz" \
    "https://github.com/frida/frida/releases/download/$FRIDA_VER/frida-server-$FRIDA_VER-android-x86_64.xz"
  unxz -f "$FS.xz"
fi

# --- mitmproxy CA (generated on first run) -------------------------------
MITM_CA="$HOME/.mitmproxy/mitmproxy-ca-cert.pem"
if [ ! -f "$MITM_CA" ]; then
  echo "[*] Generating mitmproxy CA"
  timeout 5 mitmdump >/dev/null 2>&1 || true
fi
[ -f "$MITM_CA" ] || { echo "mitmproxy CA not generated at $MITM_CA"; exit 1; }
CA_HASH="$(openssl x509 -inform PEM -subject_hash_old -in "$MITM_CA" | head -1)"

cleanup() {
  echo "[*] Stopping"
  [ -n "${MITM_PID:-}" ] && kill "$MITM_PID" 2>/dev/null || true
  [ -n "${WEB_PID:-}" ] && kill "$WEB_PID" 2>/dev/null || true
  [ -n "${EMU_PID:-}" ] && kill "$EMU_PID" 2>/dev/null || true
}
trap cleanup EXIT

# --- Boot emulator -------------------------------------------------------
# Interactive mode shows the window so you can drive the app; automated mode runs headless.
WINDOW=(-no-window); [ "$MODE" = interactive ] && WINDOW=()
echo "[*] Booting $AVD ($MODE mode)"
pkill -f "[q]emu-system" 2>/dev/null || true
sleep 2
"$A" kill-server 2>/dev/null || true
setsid nohup "$E" -avd "$AVD" -no-snapshot -wipe-data -no-audio "${WINDOW[@]}" \
  -gpu swiftshader_indirect \
  >"$OUT/emulator.log" 2>&1 </dev/null &
EMU_PID=$!
for _ in $(seq 1 60); do
  [ "$(adb shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = 1 ] && break
  kill -0 "$EMU_PID" 2>/dev/null || { echo "Emulator died, see $OUT/emulator.log"; exit 1; }
  sleep 5
done
adb_root
echo "[*] Device up: API $(adb shell getprop ro.build.version.sdk | tr -d '\r')"

# --- Install proxy CA into the system store via tmpfs --------------------
echo "[*] Installing mitmproxy CA (tmpfs over system cacerts)"
adb push "$MITM_CA" "/data/local/tmp/$CA_HASH.0" >/dev/null
adb shell "mkdir -p /data/local/tmp/cacerts && cp /system/etc/security/cacerts/* /data/local/tmp/cacerts/ 2>/dev/null; \
  cp /data/local/tmp/$CA_HASH.0 /data/local/tmp/cacerts/ && \
  mount -t tmpfs tmpfs /system/etc/security/cacerts && \
  cp /data/local/tmp/cacerts/* /system/etc/security/cacerts/ && \
  chmod 644 /system/etc/security/cacerts/* && \
  chown root:root /system/etc/security/cacerts/* && \
  chcon u:object_r:system_security_cacerts_file:s0 /system/etc/security/cacerts/* 2>/dev/null; true"

# --- Start frida-server --------------------------------------------------
echo "[*] Starting frida-server"
adb push "$FS" /data/local/tmp/frida-server >/dev/null
adb shell chmod 755 /data/local/tmp/frida-server
adb shell "setsid /data/local/tmp/frida-server >/dev/null 2>&1 &"
sleep 3

# --- Start proxy capture and point the device at it ----------------------
# A global proxy via settings is honoured by apps; the emulator -http-proxy flag is not.
# Interactive mode uses mitmweb so you watch traffic live; both write the same flows file.
if [ "$MODE" = interactive ]; then
  echo "[*] Starting mitmweb on :$PROXY_PORT (live UI at http://127.0.0.1:8081)"
  setsid nohup mitmweb --no-web-open-browser --web-host 127.0.0.1 --web-port 8081 \
    --listen-host 0.0.0.0 -p "$PROXY_PORT" -w "$OUT/traffic.flows" \
    >"$OUT/traffic.log" 2>&1 </dev/null &
else
  echo "[*] Starting mitmproxy capture on :$PROXY_PORT"
  setsid nohup mitmdump --listen-host 0.0.0.0 -p "$PROXY_PORT" \
    -w "$OUT/traffic.flows" --set console_eventlog_verbosity=info \
    >"$OUT/traffic.log" 2>&1 </dev/null &
fi
MITM_PID=$!
sleep 2
adb shell settings put global http_proxy "$HOST_FROM_GUEST:$PROXY_PORT"
echo "[*] Device proxy: $(adb shell settings get global http_proxy | tr -d '\r')"

# --- Install and launch the app under frida unpinning --------------------
list_pkgs() { adb shell pm list packages -3 2>/dev/null | sed 's/package://' | tr -d '\r' | sort; }

echo "[*] Installing APK"
list_pkgs >"$OUT/pkgs-before.txt" || true
adb install -r -g "$APK" >"$OUT/install.log" 2>&1 || { echo "Install failed:"; cat "$OUT/install.log"; exit 1; }
# Derive the package name from what appeared after install (no aapt/build-tools needed).
list_pkgs >"$OUT/pkgs-after.txt" || true
PKG="$(comm -13 "$OUT/pkgs-before.txt" "$OUT/pkgs-after.txt" | head -1)"
[ -n "$PKG" ] || PKG="$(tail -1 "$OUT/pkgs-after.txt")"
[ -n "$PKG" ] || { echo "Could not determine package name"; exit 1; }
echo "[*] Package: $PKG"

echo "[*] Launching $PKG under frida SSL-unpinning"
eval "$FRIDA frida -U -f '$PKG' -l '$HERE/frida-unpin.js' -o '$OUT/frida.log'" >/dev/null 2>&1 &
FRIDA_PID=$!

if [ "$MODE" = interactive ]; then
  echo
  echo "  >>> Emulator window is open. Log in and use the app (your phase 3)."
  echo "  >>> Watch traffic live at http://127.0.0.1:8081"
  echo "  >>> Press Ctrl+C here when done to stop and collect the summary."
  trap 'STOP=1' INT
  while [ -z "${STOP:-}" ]; do sleep 1; kill -0 "$FRIDA_PID" 2>/dev/null || break; done
  trap - INT
else
  echo "[*] Capturing ${CAPTURE}s with light interaction"
  # Gentle monkey: no system keys, so it drives the app without crashing it out.
  ( sleep 8; adb shell monkey -p "$PKG" --pct-syskeys 0 --throttle 600 -v 40 \
      >"$OUT/monkey.log" 2>&1 || true ) &
  sleep "$CAPTURE"
fi
kill "$FRIDA_PID" 2>/dev/null || true
adb shell settings delete global http_proxy 2>/dev/null || true

# --- Collect artifacts ---------------------------------------------------
echo "[*] Collecting logcat, app storage, screenshot"
adb logcat -d >"$OUT/logcat.txt" 2>/dev/null || true
adb shell "run-as $PKG tar -cf - . 2>/dev/null || tar -cf - /data/data/$PKG 2>/dev/null" >"$OUT/appdata.tar" 2>/dev/null || true
adb exec-out screencap -p >"$OUT/screen.png" 2>/dev/null || true

# --- Summarize -----------------------------------------------------------
echo
echo "================ DYNAMIC RECON SUMMARY ================"
SECRET_RE='password|passwd|pwd|token|secret|api[_-]?key|authorization|bearer|session|jwt|refresh'

python3 "$HERE/flows-summary.py" "$OUT/traffic.flows" 2>/dev/null \
  || echo "  (could not parse traffic.flows; open it with: mitmweb -r $OUT/traffic.flows)"

echo
echo "--- Possible secrets in logcat ---"
grep -aiE "$SECRET_RE" "$OUT/logcat.txt" 2>/dev/null | grep -iv "no api\|getprop" | head -10 | cut -c1-160 | sed 's/^/  /' || echo "  none"

echo
echo "--- App storage (files + grep for secrets) ---"
if [ -s "$OUT/appdata.tar" ]; then
  tar -tf "$OUT/appdata.tar" 2>/dev/null | grep -iE 'shared_prefs|databases|\.xml$|\.db$|\.sqlite' | head -15 | sed 's/^/  /'
  echo "  -- strings matching secrets --"
  tar -xOf "$OUT/appdata.tar" 2>/dev/null | strings | grep -aiE "$SECRET_RE" | head -10 | cut -c1-160 | sed 's/^/  /' || true
else
  echo "  (could not pull /data/data/$PKG)"
fi

echo
echo "--- Exported components (from dumpsys) ---"
adb shell dumpsys package "$PKG" 2>/dev/null | grep -iE 'exported=true' | head -10 | sed 's/^/  /' || echo "  none or unavailable"
echo "======================================================"
echo "Artifacts : $OUT"
echo "  traffic.flows  open with:  mitmweb -r $OUT/traffic.flows"
echo "  appdata.tar    extract and inspect shared_prefs / databases"
echo "  logcat.txt  frida.log  monkey.log  screen.png"
