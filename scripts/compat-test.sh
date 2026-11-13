#!/usr/bin/env bash
# compat-test.sh: light compatibility check of one APK on several Android API levels.
# Usage: ./compat-test.sh app.apk 33 34 35 36
# Per API level it boots a headless emulator, installs the APK, launches it, waits, and records
# one of: INSTALL_FAIL, CRASH, NOT_RUNNING, RUNNING. One emulator at a time keeps RAM use low.
# This is a functional smoke test, not a pentest: no root, no hooks, no proxy.
# Must be executed, not sourced: with set -e a sourced exit would close your shell.
(return 0 2>/dev/null) && { echo "Run it, don't source it:  bash $0 <args>" >&2; return 1; }
set -euo pipefail

[ "$#" -ge 2 ] || { echo "Usage: $0 <apk> <api> [<api> ...]"; exit 1; }
[ "$(id -u)" -ne 0 ] || { echo "Do not run as root."; exit 1; }

APK="$(realpath "$1")"; shift
[ -f "$APK" ] || { echo "APK not found: $APK"; exit 1; }

SDK="$HOME/Android/Sdk"
export PATH="$SDK/platform-tools:$SDK/emulator:$SDK/cmdline-tools/latest/bin:$PATH"
for tool in adb emulator sdkmanager avdmanager aapt; do
  command -v "$tool" >/dev/null || { echo "Missing tool: $tool (run setup-mobsf.sh, aapt comes from apt)"; exit 1; }
done

PORT=5580                       # differs from the 5554 emulator used by MobSF
SERIAL="emulator-$PORT"
SETTLE=20                       # seconds to let the app run before checking
PKG="$(aapt dump badging "$APK" | sed -n "s/^package: name='\([^']*\)'.*/\1/p")"
[ -n "$PKG" ] || { echo "Cannot read package name from $APK"; exit 1; }

OUT="compat_${PKG}_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUT"
RESULTS="$OUT/results.md"
echo "Package: $PKG" | tee "$OUT/summary.txt"
aapt dump badging "$APK" | grep -E "^(sdkVersion|targetSdkVersion)" | tee -a "$OUT/summary.txt"
echo "Native ABIs: $(unzip -l "$APK" | grep -oE 'lib/[^/]+/' | sort -u | tr '\n' ' ')" | tee -a "$OUT/summary.txt"
echo "(x86_64 emulator: an APK with only arm libraries may fail here for reasons unrelated to the app)"
printf '| API | Result | Detail |\n|---|---|---|\n' > "$RESULTS"

EMU=""
stop_emulator() {
  [ -z "$EMU" ] || { adb -s "$SERIAL" emu kill >/dev/null 2>&1 || true; wait "$EMU" 2>/dev/null || true; EMU=""; }
}
trap stop_emulator EXIT

for API in "$@"; do
  echo "[*] API $API"
  AVD="compat-api$API"
  IMG="system-images;android-$API;google_apis_playstore;x86_64"

  if ! sdkmanager "platforms;android-$API" "$IMG" >"$OUT/sdkmanager-$API.log" 2>&1; then
    echo "| $API | SKIPPED | system image $IMG not available, see sdkmanager-$API.log |" >> "$RESULTS"
    continue
  fi
  avdmanager list avd -c | grep -qx "$AVD" \
    || echo no | avdmanager create avd -n "$AVD" -d pixel_5 -k "$IMG" >/dev/null

  emulator -avd "$AVD" -port "$PORT" -no-window -no-snapshot -no-audio -wipe-data \
    >"$OUT/emulator-$API.log" 2>&1 &
  EMU=$!

  adb -s "$SERIAL" wait-for-device
  BOOTED=0
  for _ in $(seq 150); do   # 150 x 2 s = 5 min
    [ "$(adb -s "$SERIAL" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = 1 ] && { BOOTED=1; break; }
    sleep 2
  done
  if [ "$BOOTED" -ne 1 ]; then
    echo "| $API | SKIPPED | emulator did not boot in 5 min, see emulator-$API.log |" >> "$RESULTS"
    stop_emulator; continue
  fi

  INSTALL="$(adb -s "$SERIAL" install -r "$APK" 2>&1 | tr -d '\r' | tail -n 1)"
  if [ "$INSTALL" != "Success" ]; then
    echo "| $API | INSTALL_FAIL | ${INSTALL//|/\\|} |" >> "$RESULTS"
    stop_emulator; continue
  fi

  adb -s "$SERIAL" logcat -c
  adb -s "$SERIAL" shell monkey -p "$PKG" -c android.intent.category.LAUNCHER 1 >/dev/null 2>&1
  sleep "$SETTLE"
  adb -s "$SERIAL" logcat -d > "$OUT/logcat-$API.txt"

  if grep -q "FATAL EXCEPTION" "$OUT/logcat-$API.txt" && grep -A3 "FATAL EXCEPTION" "$OUT/logcat-$API.txt" | grep -q "$PKG"; then
    REASON="$(grep -A2 "FATAL EXCEPTION" "$OUT/logcat-$API.txt" | grep -m1 -E 'Exception|Error' | sed 's/^.*: //' | tr '|' '/')"
    echo "| $API | CRASH | $REASON |" >> "$RESULTS"
  elif adb -s "$SERIAL" shell pidof "$PKG" >/dev/null 2>&1; then
    echo "| $API | RUNNING | alive after ${SETTLE}s |" >> "$RESULTS"
  else
    echo "| $API | NOT_RUNNING | no crash logged, process gone, see logcat-$API.txt |" >> "$RESULTS"
  fi
  stop_emulator
done

echo
cat "$RESULTS"
echo "Logs and results in $OUT/"
