#!/usr/bin/env bash
# dynamic-scan.sh: dynamic recon of an APK on a rooted API 30 emulator.
# Boots the emulator, installs a proxy CA via tmpfs (no writable /system needed), runs frida
# SSL-unpinning, routes traffic through mitmproxy, then collects and summarizes:
#   - cleartext HTTP and intercepted HTTPS
#   - secrets left in app storage and logcat
#   - exported component behaviour
# This is recon, not proof: review every finding by hand. Run as a normal user.
#
#   scripts/dynamic-scan.sh app.apk [capture_seconds]    automated: launch, light interaction, collect
#   scripts/dynamic-scan.sh app.apk interactive          emulator window + mitmweb, Ctrl+C to stop
#   FRIDA=0 scripts/dynamic-scan.sh app.apk interactive  launch without frida
#   scripts/dynamic-scan.sh app.apk interactive --burp   route through Burp on :8080 (frida off by default)
#   GPU=swiftshader_indirect scripts/dynamic-scan.sh ... fallback if GPU=host (default) fails
# Must be executed, not sourced.
(return 0 2>/dev/null) && { echo "Run it, don't source it:  bash $0 <args>" >&2; return 1; }
set -euo pipefail

[ "$(id -u)" -ne 0 ] || { echo "Run as a normal user, not root."; exit 1; }
BURP=0; POSITIONAL=()
for arg in "$@"; do
  case "$arg" in
    --burp) BURP=1 ;;
    *) POSITIONAL+=("$arg") ;;
  esac
done
APK="${POSITIONAL[0]:-}"
MODE="auto"; CAPTURE="${POSITIONAL[1]:-90}"
[ "${POSITIONAL[1]:-}" = "interactive" ] && MODE="interactive"
[ -n "$APK" ] && [ -f "$APK" ] || { echo "Usage: $0 path/to/app.apk [capture_seconds|interactive] [--burp]"; exit 1; }

# FRIDA is the 0/1 switch. The command itself is FRIDA_CMD (they used to share a name,
# which made the switch always evaluate to "off").
if [ "$BURP" = 1 ]; then : "${FRIDA:=0}"; else : "${FRIDA:=1}"; fi
: "${GPU:=host}"

HERE="$(cd "$(dirname "$0")" && pwd)"
SDK="$HOME/Android/Sdk"
AVD="mobsf-api30"
API=30
IMAGE="system-images;android-$API;google_apis;x86_64"
SERIAL="emulator-5554"
PROXY_PORT=8080
HOST_FROM_GUEST="10.0.2.2"
A="$SDK/platform-tools/adb"
E="$SDK/emulator/emulator"
FRIDA_CMD="cd $HOME/tools/MobSF && python3 -m poetry run"

OUT="$HOME/mobsf-out/dyn-$(basename "$APK" .apk)-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUT"
adb() { "$A" -s "$SERIAL" "$@"; }

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
[ -f "$HERE/flows-summary.py" ] || echo "[!] Missing $HERE/flows-summary.py (summary of traffic will be skipped)"
if [ "$FRIDA" = 1 ]; then
  [ -f "$HERE/frida-unpin.js" ] || { echo "Missing $HERE/frida-unpin.js"; exit 1; }
  FRIDA_VER="$(bash -c "$FRIDA_CMD frida --version" 2>/dev/null | tr -d '\r')"
  [ -n "$FRIDA_VER" ] || { echo "frida not found in MobSF poetry env"; exit 1; }
  # frida-tools 12+ (frida 16+) resumes spawned apps by default and dropped --no-pause.
  FRIDA_EXTRA=""
  if bash -c "$FRIDA_CMD frida --help" 2>&1 | grep -q -- '--no-pause'; then
    FRIDA_EXTRA="--no-pause"
  fi
fi
if [ "$BURP" = 1 ]; then
  curl -s -x "127.0.0.1:$PROXY_PORT" http://burp/cert -o /dev/null \
    || { echo "Burp proxy not reachable on 127.0.0.1:$PROXY_PORT. Start Burp with a proxy listener on 0.0.0.0:$PROXY_PORT."; exit 1; }
else
  command -v mitmdump >/dev/null || { echo "mitmdump missing: sudo apt install mitmproxy"; exit 1; }
fi

if [ ! -f "$HOME/.android/avd/$AVD.avd/config.ini" ]; then
  echo "[*] Creating $AVD (Android $API)"
  export ANDROID_SDK_ROOT="$SDK" ANDROID_HOME="$SDK"
  yes | "$SDK/cmdline-tools/latest/bin/sdkmanager" "$IMAGE" >/dev/null
  echo no | "$SDK/cmdline-tools/latest/bin/avdmanager" create avd -f -n "$AVD" -d pixel_5 -k "$IMAGE"
fi

# --- frida-server matching the client version ----------------------------
if [ "$FRIDA" = 1 ]; then
  FS="$HOME/tools/frida-server-$FRIDA_VER-x86_64"
  if [ ! -f "$FS" ]; then
    echo "[*] Downloading frida-server $FRIDA_VER"
    curl -fsSL -o "$FS.xz" \
      "https://github.com/frida/frida/releases/download/$FRIDA_VER/frida-server-$FRIDA_VER-android-x86_64.xz"
    unxz -f "$FS.xz"
  fi
fi

# --- Proxy CA to inject (Burp's or mitmproxy's) --------------------------
if [ "$BURP" = 1 ]; then
  echo "[*] Fetching Burp CA through its proxy"
  curl -s -x "127.0.0.1:$PROXY_PORT" http://burp/cert -o "$OUT/burp-ca.der" \
    && openssl x509 -inform DER -in "$OUT/burp-ca.der" -out "$OUT/burp-ca.pem" 2>/dev/null \
    || { echo "Could not fetch/convert Burp CA from http://burp/cert"; exit 1; }
  CA_PEM="$OUT/burp-ca.pem"
else
  CA_PEM="$HOME/.mitmproxy/mitmproxy-ca-cert.pem"
  if [ ! -f "$CA_PEM" ]; then
    echo "[*] Generating mitmproxy CA"
    timeout 5 mitmdump >/dev/null 2>&1 || true
  fi
  [ -f "$CA_PEM" ] || { echo "mitmproxy CA not generated at $CA_PEM"; exit 1; }
fi
CA_HASH="$(openssl x509 -inform PEM -subject_hash_old -in "$CA_PEM" | head -1)"

cleanup() {
  echo "[*] Stopping"
  # frida runs in its own session/process group (setsid), kill the whole group incl. the tail
  [ -n "${FRIDA_PID:-}" ] && kill -- "-$FRIDA_PID" 2>/dev/null || true
  [ -n "${MITM_PID:-}" ] && kill "$MITM_PID" 2>/dev/null || true
  [ -n "${EMU_PID:-}" ] && kill "$EMU_PID" 2>/dev/null || true
  pkill -f "qemu-system.*-avd $AVD" 2>/dev/null || true
}
trap cleanup EXIT

# --- Boot emulator -------------------------------------------------------
WINDOW=(-no-window); [ "$MODE" = interactive ] && WINDOW=()
echo "[*] Booting $AVD ($MODE mode, gpu=$GPU)"
pkill -f "[q]emu-system" 2>/dev/null || true
sleep 2
"$A" kill-server 2>/dev/null || true
setsid nohup "$E" -avd "$AVD" -no-snapshot -wipe-data -no-audio "${WINDOW[@]}" \
  -gpu "$GPU" -cores 4 -memory 4096 -no-boot-anim \
  >"$OUT/emulator.log" 2>&1 </dev/null &
EMU_PID=$!
for _ in $(seq 1 60); do
  [ "$(adb shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = 1 ] && break
  kill -0 "$EMU_PID" 2>/dev/null || { echo "Emulator died, see $OUT/emulator.log (try GPU=swiftshader_indirect)"; exit 1; }
  sleep 5
done
adb_root
echo "[*] Device up: API $(adb shell getprop ro.build.version.sdk | tr -d '\r')"

# Let the fresh (wiped) system settle, otherwise the first app start hits ANRs.
echo "[*] Waiting for system services to settle"
for _ in $(seq 1 30); do
  adb shell pm path android 2>/dev/null | grep -q package && break
  sleep 2
done
for s in window_animation_scale transition_animation_scale animator_duration_scale; do
  adb shell settings put global "$s" 0 2>/dev/null || true
done
sleep 15

# --- Install proxy CA into the system store via tmpfs --------------------
echo "[*] Installing proxy CA (tmpfs over system cacerts)"
adb push "$CA_PEM" "/data/local/tmp/$CA_HASH.0" >/dev/null
adb shell "mkdir -p /data/local/tmp/cacerts && cp /system/etc/security/cacerts/* /data/local/tmp/cacerts/ 2>/dev/null; \
  cp /data/local/tmp/$CA_HASH.0 /data/local/tmp/cacerts/ && \
  mount -t tmpfs tmpfs /system/etc/security/cacerts && \
  cp /data/local/tmp/cacerts/* /system/etc/security/cacerts/ && \
  chmod 644 /system/etc/security/cacerts/* && \
  chown root:root /system/etc/security/cacerts/* && \
  chcon u:object_r:system_security_cacerts_file:s0 /system/etc/security/cacerts/* 2>/dev/null; true"

# --- Start frida-server ---------------------------------------------------
if [ "$FRIDA" = 1 ]; then
  echo "[*] Starting frida-server"
  adb push "$FS" /data/local/tmp/frida-server >/dev/null
  adb shell chmod 755 /data/local/tmp/frida-server
  adb shell "setsid /data/local/tmp/frida-server >/dev/null 2>&1 &"
  sleep 3
fi

# --- Start proxy capture and point the device at it ----------------------
if [ "$BURP" = 1 ]; then
  echo "[*] Using Burp as the proxy on :$PROXY_PORT (work the traffic in Burp)"
  MITM_PID=""
elif [ "$MODE" = interactive ]; then
  echo "[*] Starting mitmweb on :$PROXY_PORT (live UI at http://127.0.0.1:8081)"
  setsid nohup mitmweb --no-web-open-browser --web-host 127.0.0.1 --web-port 8081 \
    --listen-host 0.0.0.0 -p "$PROXY_PORT" -w "$OUT/traffic.flows" --ssl-insecure \
    >"$OUT/traffic.log" 2>&1 </dev/null &
  MITM_PID=$!
else
  echo "[*] Starting mitmproxy capture on :$PROXY_PORT"
  setsid nohup mitmdump --listen-host 0.0.0.0 -p "$PROXY_PORT" \
    -w "$OUT/traffic.flows" --ssl-insecure --set console_eventlog_verbosity=info \
    >"$OUT/traffic.log" 2>&1 </dev/null &
  MITM_PID=$!
fi

# Make sure the proxy actually listens before the app (and the device proxy setting) use it,
# otherwise the app hangs on network timeouts and looks frozen.
echo "[*] Waiting for proxy on :$PROXY_PORT"
PROXY_UP=0
for _ in $(seq 1 20); do
  if (exec 3<>"/dev/tcp/127.0.0.1/$PROXY_PORT") 2>/dev/null; then PROXY_UP=1; break; fi
  sleep 1
done
[ "$PROXY_UP" = 1 ] || { echo "Proxy did not start, see $OUT/traffic.log"; exit 1; }

for _ in $(seq 1 30); do
  adb shell service check settings 2>/dev/null | grep -q "found" && break
  sleep 2
done
for _ in $(seq 1 10); do
  adb shell settings put global http_proxy "$HOST_FROM_GUEST:$PROXY_PORT" 2>/dev/null && break
  sleep 2
done
echo "[*] Device proxy: $(adb shell settings get global http_proxy | tr -d '\r')"

# --- Install and launch the app ------------------------------------------
list_pkgs() { adb shell pm list packages -3 2>/dev/null | sed 's/package://' | tr -d '\r' | sort; }

echo "[*] Installing APK"
list_pkgs >"$OUT/pkgs-before.txt" || true
adb install -r -g "$APK" >"$OUT/install.log" 2>&1 || { echo "Install failed:"; cat "$OUT/install.log"; exit 1; }
list_pkgs >"$OUT/pkgs-after.txt" || true
PKG="$(comm -13 "$OUT/pkgs-before.txt" "$OUT/pkgs-after.txt" | head -1)"
[ -n "$PKG" ] || PKG="$(tail -1 "$OUT/pkgs-after.txt")"
[ -n "$PKG" ] || { echo "Could not determine package name"; exit 1; }
echo "[*] Package: $PKG"

FRIDA_PID=""
if [ "$FRIDA" = 1 ]; then
  echo "[*] Launching $PKG under frida SSL-unpinning"
  # frida -f opens a REPL: keep stdin open (tail) so it does not exit in the background.
  # Own session (setsid) so cleanup can kill frida and tail together. Errors go to frida.stderr.
  setsid bash -c "tail -f /dev/null | $FRIDA_CMD frida -U -f '$PKG' -l '$HERE/frida-unpin.js' $FRIDA_EXTRA -o '$OUT/frida.log'" \
    >"$OUT/frida.stderr" 2>&1 </dev/null &
  FRIDA_PID=$!
  sleep 8
  if grep -q "frida-unpin\] installed" "$OUT/frida.log" 2>/dev/null; then
    echo "[*] $(grep -a 'frida-unpin\] installed' "$OUT/frida.log" | head -1)"
  else
    echo "[!] frida script did not report in $OUT/frida.log yet, check $OUT/frida.stderr"
  fi
else
  echo "[*] Launching $PKG without frida (FRIDA=0): any pinned HTTPS stays hidden"
  adb shell monkey -p "$PKG" -c android.intent.category.LAUNCHER 1 >/dev/null 2>&1 || true
fi

if [ "$MODE" = interactive ]; then
  echo
  echo "  >>> Emulator window is open. Log in and use the app (your phase 3)."
  if [ "$BURP" = 1 ]; then echo "  >>> Watch traffic in Burp (Proxy > HTTP history), work it in Repeater"; else echo "  >>> Watch traffic live at http://127.0.0.1:8081"; fi
  echo "  >>> Press Ctrl+C here when done to stop and collect the summary."
  trap 'STOP=1' INT
  while [ -z "${STOP:-}" ]; do
    sleep 1 || true
    if [ -n "$FRIDA_PID" ] && ! kill -0 "$FRIDA_PID" 2>/dev/null; then
      echo "[!] frida exited, see $OUT/frida.stderr"; break
    fi
  done
  trap - INT
else
  echo "[*] Capturing ${CAPTURE}s with light interaction"
  ( sleep 10; adb shell monkey -p "$PKG" --pct-syskeys 0 --throttle 800 \
      --ignore-crashes --ignore-timeouts --ignore-security-exceptions -v 40 \
      >"$OUT/monkey.log" 2>&1 || true ) &
  sleep "$CAPTURE"
fi
[ -n "$FRIDA_PID" ] && { kill -- "-$FRIDA_PID" 2>/dev/null || true; FRIDA_PID=""; }
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

if [ "$BURP" = 1 ]; then
  echo "  (traffic captured in Burp, use its Proxy history, Repeater and Target tabs)"
else
  python3 "$HERE/flows-summary.py" "$OUT/traffic.flows" 2>/dev/null \
    || echo "  (could not parse traffic.flows; open it with: mitmweb -r $OUT/traffic.flows)"
fi

echo
echo "--- Possible secrets in logcat ---"
grep -aiE "$SECRET_RE" "$OUT/logcat.txt" 2>/dev/null | grep -iv "no api\|getprop" | head -10 | cut -c1-160 | sed 's/^/  /' || echo "  none"

echo
echo "--- App storage (files + grep for secrets) ---"
if [ -s "$OUT/appdata.tar" ]; then
  tar -tf "$OUT/appdata.tar" 2>/dev/null | grep -iE 'shared_prefs|databases|\.xml$|\.db$|\.sqlite' | head -15 | sed 's/^/  /' || true
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
[ "$BURP" = 1 ] || echo "  traffic.flows  open with:  mitmweb -r $OUT/traffic.flows"
echo "  appdata.tar    extract and inspect shared_prefs / databases"
echo "  logcat.txt  frida.log  frida.stderr  monkey.log  screen.png"
