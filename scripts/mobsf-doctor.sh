#!/usr/bin/env bash
# mobsf-doctor.sh: read-only check that MobSF and the emulator are set up correctly.
# Run as the same user that runs mobsf-dynamic.sh. Changes nothing.
# Must be executed, not sourced: with set -e a sourced exit would close your shell.
(return 0 2>/dev/null) && { echo "Run it, don't source it:  bash $0 <args>" >&2; return 1; }
set -uo pipefail

SDK="$HOME/Android/Sdk"
AVD="mobsf-api28"
API=28
MOBSF_DIR="$HOME/tools/MobSF"
SERIAL="${MOBSF_ANALYZER_IDENTIFIER:-emulator-5554}"
ADB="$SDK/platform-tools/adb"

fails=0 warns=0
ok()   { printf '  [ OK ] %s\n' "$1"; }
warn() { printf '  [WARN] %s\n' "$1"; warns=$((warns + 1)); }
fail() { printf '  [FAIL] %s\n' "$1"; fails=$((fails + 1)); }

echo "== User and system"
if [ "$(id -u)" -eq 0 ]; then
  fail "running as root: data would go to /root/.MobSF. Use your normal user"
else
  ok "user $USER"
fi
[ "$(uname -m)" = x86_64 ] && ok "x86_64" || fail "$(uname -m): no local emulator, see setup-mobsf.sh"
virt="$(systemd-detect-virt 2>/dev/null || true)"
ok "virtualization: ${virt:-none (bare metal)}"
mem_gb=$(( $(awk '/MemTotal/ {print $2}' /proc/meminfo) / 1024 / 1024 ))
[ "$mem_gb" -ge 8 ] && ok "RAM ${mem_gb} GB" || warn "RAM ${mem_gb} GB: emulator needs 4 GB, give the VM 8 GB or more"
free_gb=$(df --output=avail -BG "$HOME" | tail -1 | tr -dc '0-9')
[ "$free_gb" -ge 15 ] && ok "free disk ${free_gb} GB" || warn "free disk ${free_gb} GB: SDK, image and AVD need about 15 GB"

echo "== KVM"
if [ -e /dev/kvm ]; then
  ok "/dev/kvm exists"
  if [ -r /dev/kvm ] && [ -w /dev/kvm ]; then
    ok "access to /dev/kvm"
  else
    fail "no access to /dev/kvm: 'sudo usermod -aG kvm \$USER', then log out and in"
  fi
else
  fail "/dev/kvm missing: enable nested virtualization (VMware: Virtualize Intel VT-x/EPT, VirtualBox: Enable Nested VT-x/AMD-V)"
fi
if grep -Eq '(vmx|svm)' /proc/cpuinfo; then
  ok "CPU exposes vmx/svm"
else
  fail "CPU flags vmx/svm not visible: virtualization is off for this machine"
fi

echo "== Python and Java"
if command -v python3.13 >/dev/null || command -v python3.12 >/dev/null; then
  ok "$(command -v python3.13 || command -v python3.12) (used for MobSF; python3 itself is $(python3 -V 2>&1))"
else
  fail "no python3.12 or python3.13: MobSF needs one of them"
fi
command -v java >/dev/null && ok "java found" || fail "java missing: sudo apt install default-jre"

echo "== MobSF install and data"
[ -d "$MOBSF_DIR/.git" ] && ok "MobSF in $MOBSF_DIR" || fail "MobSF not found in $MOBSF_DIR: run setup-mobsf.sh"
if [ -d "$HOME/.MobSF" ]; then
  [ -O "$HOME/.MobSF" ] && ok "~/.MobSF owned by you" || fail "~/.MobSF not owned by you: sudo chown -R \$USER:\$USER ~/.MobSF"
  if [ -f "$HOME/.MobSF/db.sqlite3" ]; then
    ok "scan database $(du -h "$HOME/.MobSF/db.sqlite3" | cut -f1), modified $(date -r "$HOME/.MobSF/db.sqlite3" '+%F %T')"
  else
    warn "no db.sqlite3 in ~/.MobSF: MobSF was never started or setup.sh wiped it"
  fi
else
  warn "~/.MobSF missing: normal before the first start, a problem if you scanned before"
fi
for d in "$HOME/tools" "$SDK"; do
  [ ! -e "$d" ] || [ -O "$d" ] || fail "$d not owned by you (earlier sudo run?): sudo chown -R \$USER:\$USER $d"
done
if pgrep -u root -f 'gunicorn.*MobSF' >/dev/null; then
  fail "MobSF runs as root: stop it and start via mobsf-dynamic.sh without sudo"
fi
[ -d /root/.MobSF ] && warn "/root/.MobSF exists: scans done via sudo are stored there, not in ~/.MobSF"
if ss -ltn 2>/dev/null | grep -q ':8000 '; then
  ok "port 8000 listening (MobSF running)"
else
  warn "port 8000 not listening: MobSF not running"
fi

echo "== Android SDK and AVD"
for t in platform-tools/adb emulator/emulator cmdline-tools/latest/bin/sdkmanager; do
  [ -x "$SDK/$t" ] && ok "$t" || fail "$SDK/$t missing: run setup-mobsf.sh"
done
img="$SDK/system-images/android-$API/google_apis/x86_64"
if [ -d "$img" ]; then
  ok "system image android-$API google_apis (rootable)"
else
  fail "image android-$API google_apis x86_64 missing (the Play Store image cannot adb root)"
fi
cfg="$HOME/.android/avd/$AVD.avd/config.ini"
if [ -f "$cfg" ]; then
  ok "AVD $AVD, $(grep '^hw.ramSize' "$cfg" | tr -d ' ' || echo 'default RAM')"
else
  fail "AVD $AVD missing: re-run the AVD step of setup-mobsf.sh"
fi
if dpkg -s adb >/dev/null 2>&1; then
  warn "apt 'adb' installed next to SDK adb: two servers can fight over the device ('sudo apt remove adb')"
fi

echo "== Emulator and adb"
if pgrep -f "qemu-system.*-avd $AVD|emulator.*-avd $AVD" >/dev/null; then
  ok "emulator process running"
else
  warn "emulator not running (mobsf-dynamic.sh starts it)"
fi
if [ -x "$ADB" ]; then
  state="$("$ADB" -s "$SERIAL" get-state 2>/dev/null || true)"
  if [ "$state" = device ]; then
    ok "adb sees $SERIAL"
    boot="$("$ADB" -s "$SERIAL" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')"
    [ "$boot" = 1 ] && ok "boot completed" || fail "emulator not booted yet (sys.boot_completed='$boot')"
    "$ADB" -s "$SERIAL" shell id 2>/dev/null | grep -q 'uid=0' && ok "adb shell is root" || warn "adb shell is not root: mobsf-dynamic.sh runs 'adb root'"
    sdk="$("$ADB" -s "$SERIAL" shell getprop ro.build.version.sdk 2>/dev/null | tr -d '\r')"
    [ "$sdk" = "$API" ] && ok "Android API $sdk" || warn "Android API '$sdk', expected $API"
  else
    warn "adb does not see $SERIAL (state: ${state:-none})"
    "$ADB" devices | sed 's/^/         /'
  fi
fi
if [ -f "/tmp/emulator-$AVD.log" ]; then
  echo "  last emulator log lines:"
  tail -n 8 "/tmp/emulator-$AVD.log" | sed 's/^/         /'
fi

echo
echo "Result: $fails failed, $warns warnings"
[ "$fails" -eq 0 ]
