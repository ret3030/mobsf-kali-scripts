#!/usr/bin/env bash
# mobsf-dynamic.sh: start the emulator in the state MobSF dynamic analysis needs, then MobSF.
# Run after setup-mobsf.sh, as a normal user. Ctrl+C stops MobSF and the emulator.
set -euo pipefail

[ "$(id -u)" -ne 0 ] || { echo "Do not run as root."; exit 1; }

SDK="$HOME/Android/Sdk"
AVD="mobsf-api30"
MOBSF_DIR="$HOME/tools/MobSF"
PORT=8000

if [ -x "$SDK/platform-tools/adb" ]; then
  export PATH="$SDK/platform-tools:$SDK/emulator:$PATH"
fi
export MOBSF_ADB_BINARY="$(command -v adb)"
export MOBSF_ANALYZER_IDENTIFIER="${MOBSF_ANALYZER_IDENTIFIER:-emulator-5554}"

# A stale adb server or a leftover MobSF state is the usual cause of "cannot run dynamic analysis".
adb kill-server; adb start-server

if [ -x "$SDK/emulator/emulator" ]; then
  # -writable-system lets MobSF install its CA into the system store; -no-snapshot avoids stale state.
  emulator -avd "$AVD" -writable-system -no-snapshot -no-audio >"/tmp/emulator-$AVD.log" 2>&1 &
  EMU=$!
  trap 'kill $EMU 2>/dev/null || true' EXIT
fi

echo "[*] Waiting for $MOBSF_ANALYZER_IDENTIFIER to boot"
adb -s "$MOBSF_ANALYZER_IDENTIFIER" wait-for-device
until [ "$(adb -s "$MOBSF_ANALYZER_IDENTIFIER" shell getprop sys.boot_completed | tr -d '\r')" = 1 ]; do sleep 2; done

echo "[*] Root + writable system"
adb -s "$MOBSF_ANALYZER_IDENTIFIER" root >/dev/null
if ! adb -s "$MOBSF_ANALYZER_IDENTIFIER" remount >/dev/null 2>&1; then
  adb -s "$MOBSF_ANALYZER_IDENTIFIER" disable-verity
  adb -s "$MOBSF_ANALYZER_IDENTIFIER" reboot
  adb -s "$MOBSF_ANALYZER_IDENTIFIER" wait-for-device
  until [ "$(adb -s "$MOBSF_ANALYZER_IDENTIFIER" shell getprop sys.boot_completed | tr -d '\r')" = 1 ]; do sleep 2; done
  adb -s "$MOBSF_ANALYZER_IDENTIFIER" root >/dev/null
  adb -s "$MOBSF_ANALYZER_IDENTIFIER" remount
fi

echo "[*] Device ready: API $(adb -s "$MOBSF_ANALYZER_IDENTIFIER" shell getprop ro.build.version.sdk | tr -d '\r')"
echo "[*] MobSF on http://127.0.0.1:$PORT (localhost only)"
cd "$MOBSF_DIR"
./run.sh "127.0.0.1:$PORT"
