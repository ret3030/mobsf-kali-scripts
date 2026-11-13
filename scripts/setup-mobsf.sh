#!/usr/bin/env bash
# setup-mobsf.sh: one-time install of MobSF (native) plus an Android emulator for dynamic analysis.
# Run as a normal user, NOT with sudo. Only the apt step asks for sudo itself.
# Everything lives in the home directory, so MobSF never needs root.
set -euo pipefail

[ "$(id -u)" -ne 0 ] || { echo "Run as a normal user, not root (root-owned files in ~ break MobSF)."; exit 1; }

TOOLS="$HOME/tools"
MOBSF_DIR="$TOOLS/MobSF"
SDK="$HOME/Android/Sdk"
AVD="mobsf-api30"
API=30
# Pinned cmdline-tools build; bump it if Google removes the file.
CMDLINE_TOOLS=11076708

ARCH="$(uname -m)"

echo "[*] Python version (MobSF needs 3.12 or 3.13)"
PYMINOR="$(python3 -c 'import sys; print(sys.version_info.minor)')"
if [ "$PYMINOR" -lt 12 ] || [ "$PYMINOR" -gt 13 ]; then
  echo "    python3 is 3.$PYMINOR. Install 3.12/3.13 (for example with uv: 'uv python install 3.13') and re-run."
  exit 1
fi

echo "[*] apt packages"
sudo apt update
sudo apt install -y git curl unzip default-jre python3-dev python3-venv python3-pip \
  build-essential libffi-dev libssl-dev libxml2-dev libxslt1-dev libjpeg-dev zlib1g-dev \
  wkhtmltopdf libpulse0 libnss3 libgl1

echo "[*] MobSF"
mkdir -p "$TOOLS"
[ -d "$MOBSF_DIR/.git" ] || git clone https://github.com/MobSF/Mobile-Security-Framework-MobSF.git "$MOBSF_DIR"
# MobSF's setup.sh runs clean.sh, which deletes ~/.MobSF (scan history, uploads, DB).
# Run it only on a fresh install; update later with 'git pull', not by re-running setup.sh.
if [ -f "$HOME/.MobSF/db.sqlite3" ]; then
  echo "    ~/.MobSF already exists, skipping MobSF setup.sh so scan history is kept."
else
  (cd "$MOBSF_DIR" && ./setup.sh)
fi

if [ "$ARCH" != "x86_64" ]; then
  # Google ships no Linux arm64 emulator or platform-tools, so use apt adb and a remote emulator.
  echo "[!] $ARCH: no local emulator possible. Installing adb from apt only."
  sudo apt install -y adb
  cat <<EOF

Run the emulator on the host (macOS) instead, then on the host:
    adb kill-server; adb -a -P 5037 nodaemon server
and here before scripts/mobsf-dynamic.sh:
    export ADB_SERVER_SOCKET=tcp:<host-ip>:5037
    export MOBSF_ANALYZER_IDENTIFIER=emulator-5554
EOF
  exit 0
fi

echo "[*] KVM access (emulator is unusably slow without it)"
if [ ! -e /dev/kvm ]; then
  echo "    /dev/kvm missing: enable virtualization (nested virtualization if Kali is a VM)."
elif ! id -nG | grep -qw kvm; then
  sudo usermod -aG kvm "$USER"
  echo "    added $USER to group kvm: log out and back in before starting the emulator."
fi

echo "[*] Android SDK in $SDK"
if [ ! -x "$SDK/cmdline-tools/latest/bin/sdkmanager" ]; then
  mkdir -p "$SDK/cmdline-tools"
  ZIP="$(mktemp --suffix=.zip)"
  curl -sSfL -o "$ZIP" "https://dl.google.com/android/repository/commandlinetools-linux-${CMDLINE_TOOLS}_latest.zip"
  unzip -q "$ZIP" -d "$SDK/cmdline-tools"
  mv "$SDK/cmdline-tools/cmdline-tools" "$SDK/cmdline-tools/latest"
  rm "$ZIP"
fi
SDKM="$SDK/cmdline-tools/latest/bin/sdkmanager"
yes | "$SDKM" --licenses >/dev/null || true
# google_apis (not google_apis_playstore): the Play image has no adb root.
"$SDKM" "platform-tools" "emulator" "platforms;android-$API" "system-images;android-$API;google_apis;x86_64"

echo "[*] AVD $AVD"
echo no | "$SDK/cmdline-tools/latest/bin/avdmanager" create avd -f -n "$AVD" -d pixel_5 \
  -k "system-images;android-$API;google_apis;x86_64"
CFG="$HOME/.android/avd/$AVD.avd/config.ini"
sed -i '/^hw.ramSize/d;/^disk.dataPartition.size/d' "$CFG"
printf 'hw.ramSize=4096\ndisk.dataPartition.size=8G\n' >> "$CFG"

echo "[*] Avoid two adb servers fighting over the device"
if dpkg -s adb >/dev/null 2>&1; then
  echo "    apt 'adb' is installed (from setup-kali.sh). The SDK adb is used by mobsf-dynamic.sh;"
  echo "    if 'adb devices' flaps, run: sudo apt remove adb"
fi

cat <<EOF

[*] Done. MobSF login is mobsf / mobsf: change it in the web UI after the first start.
    Start every session with: scripts/mobsf-dynamic.sh
EOF
