#!/usr/bin/env bash
# setup-kali.sh - install the Android pentest toolkit on Kali Linux.
# Must be executed, not sourced: with set -e a sourced exit would close your shell.
(return 0 2>/dev/null) && { echo "Run it, don't source it:  bash $0 <args>" >&2; return 1; }
set -euo pipefail

echo "[*] apt packages"
sudo apt update
sudo apt install -y apktool jadx apksigner aapt adb default-jre python3-pip ripgrep radare2

echo "[*] python tools (frida, objection, semgrep)"
pipx install frida-tools || pip3 install --user frida-tools
pipx install objection   || pip3 install --user objection
pipx install semgrep     || pip3 install --user semgrep

echo "[*] MobSF (docker image)"
if command -v docker >/dev/null; then
  sudo docker pull opensecurity/mobile-security-framework-mobsf:latest
else
  echo "    docker not installed; skip MobSF or install docker.io"
fi

echo "[*] trufflehog (optional, verified-secret scanning)"
curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \
  | sudo sh -s -- -b /usr/local/bin || echo "    trufflehog install skipped"

echo
echo "[*] Verify:"
echo "    jadx --version ; frida --version ; objection version ; adb devices"
