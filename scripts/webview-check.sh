#!/usr/bin/env bash
# webview-check.sh: find risky WebView settings MobSF does not flag (mixed content, JS bridge,
# file access, cookies, debugging) in an APK's decompiled code, with file:line evidence.
# Reuses MobSF's decompiled output if the APK was already scanned; otherwise runs jadx.
#
# Usage: scripts/webview-check.sh path/to/app.apk
# Must be executed, not sourced: with set -e a sourced exit would close your shell.
(return 0 2>/dev/null) && { echo "Run it, don't source it:  bash $0 <args>" >&2; return 1; }
set -euo pipefail

APK="${1:-}"
[ -n "$APK" ] && [ -f "$APK" ] || { echo "Usage: $0 path/to/app.apk"; exit 1; }

MD5="$(md5sum "$APK" | cut -d' ' -f1)"
SRC="$HOME/.MobSF/uploads/$MD5/java_source"
if [ ! -d "$SRC" ]; then
  SRC="$(mktemp -d)/src"
  echo "[*] Not in MobSF cache, decompiling with jadx (this can take a minute)"
  jadx -d "$(dirname "$SRC")" --no-res -q "$APK" >/dev/null 2>&1 || true
  SRC="$(dirname "$SRC")/sources"
  [ -d "$SRC" ] || { echo "jadx produced no sources"; exit 1; }
else
  echo "[*] Using MobSF decompiled sources for $MD5"
fi

# pattern | severity | note. The pattern is an extended regex matched against decompiled Java.
CHECKS=(
  'setWebContentsDebuggingEnabled\(true\)|HIGH|Remote WebView debugging on in release'
  'setAllowUniversalAccessFromFileURLs\(true\)|HIGH|file:// pages can read any origin'
  'setAllowFileAccessFromFileURLs\(true\)|HIGH|file:// pages can read other local files'
  'addJavascriptInterface\(|HIGH|JS-to-native bridge exposed to page content'
  'setMixedContentMode\(0\)|HIGH|MIXED_CONTENT_ALWAYS_ALLOW: HTTP content on HTTPS pages'
  'setMixedContentMode\(2\)|WARN|MIXED_CONTENT_COMPATIBILITY_MODE: may load HTTP content'
  'setAllowFileAccess\(true\)|WARN|WebView can open local files'
  'setAllowContentAccess\(true\)|WARN|WebView can read content:// providers'
  'setSavePassword\(true\)|WARN|deprecated password saving enabled'
  'setJavaScriptCanOpenWindowsAutomatically\(true\)|WARN|page can open windows without user action'
  'setAcceptThirdPartyCookies\([^)]*,[[:space:]]*true\)|INFO|third-party cookies accepted'
  'setJavaScriptEnabled\(true\)|INFO|JavaScript enabled (often required, note it)'
  'setDomStorageEnabled\(true\)|INFO|DOM storage enabled'
)

high=0; warn=0; info=0
echo
echo "================ WEBVIEW CONFIG CHECK ================"
for entry in "${CHECKS[@]}"; do
  IFS='|' read -r pat sev note <<<"$entry"
  hits="$(grep -rnE "$pat" "$SRC" 2>/dev/null || true)"
  [ -n "$hits" ] || continue
  echo
  echo "[$sev] $note"
  while IFS= read -r line; do
    file="${line%%:*}"; rest="${line#*:}"; lineno="${rest%%:*}"
    echo "    ${file#"$SRC"/}:$lineno"
    case "$sev" in HIGH) high=$((high+1));; WARN) warn=$((warn+1));; INFO) info=$((info+1));; esac
  done <<<"$hits"
done

echo
echo "-----------------------------------------------------"
echo "WebView findings: $high high, $warn warning, $info info"
if [ "$high" -eq 0 ] && [ "$warn" -eq 0 ] && [ "$info" -eq 0 ]; then
  echo "No WebView settings found (app may not use WebView)."
fi
echo "Review each in context: a setting is only a finding if the WebView loads untrusted content."
echo "====================================================="
