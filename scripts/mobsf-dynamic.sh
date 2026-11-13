#!/usr/bin/env bash
# mobsf-dynamic.sh: start the emulator in the state MobSF dynamic analysis needs, then MobSF.
# Run after setup-mobsf.sh, as a normal user. Ctrl+C stops MobSF and the emulator.
set -euo pipefail

[ "$(id -u)" -ne 0 ] || { echo "Do not run as root."; exit 1; }

SDK="$HOME/Android/Sdk"
AVD="mobsf-api28"
MOBSF_DIR="$HOME/tools/MobSF"
PORT=8000
BOOT_TIMEOUT="${BOOT_TIMEOUT:-600}"

# MobSF needs Python 3.12/3.13 but the distro default may be newer (Kali ships 3.14).
# A private shim dir makes 'python3' resolve to a supported one for MobSF's setup.sh and run.sh only.
PY="$(command -v python3.13 || command -v python3.12 || true)"
if [ -n "$PY" ]; then
  mkdir -p "$HOME/tools/pyshim" && ln -sf "$PY" "$HOME/tools/pyshim/python3"
  export PATH="$HOME/tools/pyshim:$PATH"
fi

# Install whatever is missing, so this one script is all you ever run.
HERE="$(cd "$(dirname "$0")" && pwd)"
if [ ! -x "$SDK/platform-tools/adb" ] || [ ! -x "$SDK/emulator/emulator" ] \
  || [ ! -f "$HOME/.android/avd/$AVD.avd/config.ini" ] || [ ! -d "$MOBSF_DIR/.git" ]; then
  echo "[*] Something is missing, running setup-mobsf.sh first"
  "$HERE/setup-mobsf.sh"
fi

if [ -x "$SDK/platform-tools/adb" ]; then
  export PATH="$SDK/platform-tools:$SDK/emulator:$PATH"
fi
export MOBSF_ADB_BINARY="$(command -v adb)"
export MOBSF_ANALYZER_IDENTIFIER="${MOBSF_ANALYZER_IDENTIFIER:-emulator-5554}"

# Without KVM the emulator dies (or crawls) inside a VM: enable nested virtualization in the hypervisor.
if [ ! -r /dev/kvm ] || [ ! -w /dev/kvm ]; then
  echo "No access to /dev/kvm. Enable nested virtualization (VMware: Virtualize Intel VT-x/EPT," >&2
  echo "VirtualBox: Enable Nested VT-x/AMD-V), check 'kvm-ok', and make sure you are in group kvm (id)." >&2
  exit 1
fi

# A stale adb server or a leftover MobSF state is the usual cause of "cannot run dynamic analysis".
adb kill-server; adb start-server

if [ -x "$SDK/emulator/emulator" ]; then
  # Software GL: host GL in a VM gives a grey screen and can crash the terminal. No window by default:
  # MobSF shows the screen in the browser. SHOW_EMULATOR=1 opens the window.
  WINDOW=-no-window; [ "${SHOW_EMULATOR:-0}" = 1 ] && WINDOW=
  # -writable-system lets MobSF install its CA into the system store. -wipe-data (as in MobSF's own
  # start_avd.sh) avoids stale state, which can boot-loop; scan results live on the host, not in the AVD.
  # shellcheck disable=SC2086
  "$SDK/emulator/emulator" -avd "$AVD" -writable-system -no-snapshot -wipe-data -no-audio -gpu swiftshader_indirect \
    $WINDOW >"/tmp/emulator-$AVD.log" 2>&1 &
  EMU=$!
  trap 'kill $EMU 2>/dev/null || true' EXIT
fi

# Cold boot takes 1-3 min with KVM and far longer without it, so print progress and give up eventually.
wait_boot() {
  local start=$SECONDS
  until [ "$(adb -s "$MOBSF_ANALYZER_IDENTIFIER" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = 1 ]; do
    if [ -n "${EMU:-}" ] && ! kill -0 "$EMU" 2>/dev/null; then
      echo "Emulator exited early. Last log lines:" >&2
      tail -n 15 "/tmp/emulator-$AVD.log" >&2
      exit 1
    fi
    if [ $((SECONDS - start)) -ge "$BOOT_TIMEOUT" ]; then
      echo "Not booted after ${BOOT_TIMEOUT}s (adb state: $(adb -s "$MOBSF_ANALYZER_IDENTIFIER" get-state 2>&1))." >&2
      echo "Run mobsf-doctor.sh and check /tmp/emulator-$AVD.log" >&2
      exit 1
    fi
    echo "    $((SECONDS - start))s, adb state: $(adb -s "$MOBSF_ANALYZER_IDENTIFIER" get-state 2>&1 | head -n1)"
    sleep 10
  done
}

echo "[*] Waiting for $MOBSF_ANALYZER_IDENTIFIER to boot (up to ${BOOT_TIMEOUT}s)"
wait_boot

echo "[*] Root + writable system"
adb -s "$MOBSF_ANALYZER_IDENTIFIER" root >/dev/null
sleep 3
adb -s "$MOBSF_ANALYZER_IDENTIFIER" remount >/dev/null 2>&1 || true
# Do not 'disable-verity' + 'adb reboot' here: that boot-loops newer emulators. MobSF refuses a read-only /system.
if ! adb -s "$MOBSF_ANALYZER_IDENTIFIER" shell 'touch /system/.w && rm /system/.w' 2>/dev/null; then
  echo "/system is not writable. Use a google_apis (no Play Store) API 28 image and -writable-system." >&2
  exit 1
fi

echo "[*] Device ready: API $(adb -s "$MOBSF_ANALYZER_IDENTIFIER" shell getprop ro.build.version.sdk | tr -d '\r')"
echo "[*] MobSF on http://127.0.0.1:$PORT (localhost only)"
cd "$MOBSF_DIR"
# Poetry remembers the last env it used; pin it to the supported Python so it never switches to 3.14.
[ -n "$PY" ] && python3 -m poetry env use "$PY" >/dev/null
./run.sh "127.0.0.1:$PORT"
