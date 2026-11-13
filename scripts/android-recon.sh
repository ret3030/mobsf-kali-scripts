#!/usr/bin/env bash
# android-recon.sh - read-only static recon for an authorised Android pentest.
# Usage: ./android-recon.sh target.apk
# It decodes, decompiles, and scans the APK. It never modifies the artifact.
# Must be executed, not sourced: with set -e a sourced exit would close your shell.
(return 0 2>/dev/null) && { echo "Run it, don't source it:  bash $0 <args>" >&2; return 1; }
set -euo pipefail

APK="${1:?Usage: $0 <apk>}"
[ -f "$APK" ] || { echo "APK not found: $APK"; exit 1; }

BASE="$(basename "${APK%.apk}")"
OUT="recon_${BASE}_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUT"/{decoded,jadx,scans}
echo "[*] Output: $OUT"

echo "[*] Hashing artifact"
sha256sum "$APK" | tee "$OUT/apk.sha256"

echo "[*] Decoding resources + manifest (apktool)"
apktool d -f -o "$OUT/decoded" "$APK" >/dev/null

echo "[*] Decompiling to Java (jadx)"
jadx -d "$OUT/jadx" "$APK" >/dev/null 2>&1 || echo "    jadx had non-fatal errors, output still usable"

echo "[*] Manifest + package summary (aapt)"
aapt dump badging "$APK" > "$OUT/scans/badging.txt" 2>/dev/null || true
aapt dump permissions "$APK" > "$OUT/scans/permissions.txt" 2>/dev/null || true

echo "[*] Signing / certificate info"
apksigner verify --print-certs -v "$APK" > "$OUT/scans/signing.txt" 2>&1 || true

echo "[*] Flagging risky manifest settings"
MAN="$OUT/decoded/AndroidManifest.xml"
{
  grep -nE 'android:debuggable="true"' "$MAN" && echo "  -> debuggable release?"
  grep -nE 'android:allowBackup="true"' "$MAN" && echo "  -> backups allowed"
  grep -nE 'usesCleartextTraffic="true"' "$MAN" && echo "  -> cleartext allowed"
  echo "--- exported components ---"
  grep -nE 'android:exported="true"' "$MAN" || true
} > "$OUT/scans/manifest_flags.txt" 2>/dev/null || true

echo "[*] Network Security Config"
find "$OUT/decoded/res" -iname 'network_security_config*.xml' -exec cp {} "$OUT/scans/" \; 2>/dev/null || true

echo "[*] Secret / endpoint grep across decompiled source"
PATTERNS='(api[_-]?key|secret|password|passwd|token|bearer|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_\-]{35}|-----BEGIN|firebaseio\.com|s3\.amazonaws|https?://)'
grep -rniE "$PATTERNS" "$OUT/jadx/sources" > "$OUT/scans/secrets_grep.txt" 2>/dev/null || true
grep -rniE "$PATTERNS" "$OUT/decoded/res" >> "$OUT/scans/secrets_grep.txt" 2>/dev/null || true
echo "    hits: $(wc -l < "$OUT/scans/secrets_grep.txt" 2>/dev/null || echo 0)"

echo "[*] Native libraries"
find "$OUT/decoded/lib" -name '*.so' > "$OUT/scans/native_libs.txt" 2>/dev/null || true

# Optional deeper scanners if installed
command -v semgrep >/dev/null && {
  echo "[*] semgrep (mobile + secrets rules)"
  semgrep --config p/mobile --config p/secrets "$OUT/jadx/sources" \
    --json -o "$OUT/scans/semgrep.json" >/dev/null 2>&1 || true
}
command -v trufflehog >/dev/null && {
  echo "[*] trufflehog verified secrets"
  trufflehog filesystem "$OUT/jadx/sources" --only-verified \
    > "$OUT/scans/trufflehog.txt" 2>/dev/null || true
}
command -v nuclei >/dev/null && echo "[i] nuclei present (point it at in-scope endpoints only)"

cat <<EOF

[*] Static recon done. Review:
    $OUT/scans/manifest_flags.txt   risky manifest settings
    $OUT/scans/secrets_grep.txt     hardcoded material / endpoints
    $OUT/scans/signing.txt          certificate + v1/v2/v3 signing
    $OUT/jadx/sources               decompiled code for manual review

Next, dynamic (needs a rooted device/emulator on adb):
    mobsf        : docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf
    frida        : frida-ps -U
    objection    : objection -g <package> explore
    traffic      : Burp/mitmproxy, CA in the system trust store
    exported     : adb shell am start -n <package>/<activity> ...   (observe only)
    logs         : adb logcat --pid=\$(adb shell pidof -s <package>)
    backup test  : adb backup -f backup.ab -noapk <package>   (if allowBackup=true)
EOF
