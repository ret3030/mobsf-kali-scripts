#!/usr/bin/env bash
# static-scan.sh: run MobSF static analysis on an APK from the command line and print a summary.
# Starts MobSF locally if it is not already running (no emulator needed). Run as a normal user.
#
# Usage: scripts/static-scan.sh path/to/app.apk
# Must be executed, not sourced: with set -e a sourced exit would close your shell.
(return 0 2>/dev/null) && { echo "Run it, don't source it:  bash $0 <args>" >&2; return 1; }
set -euo pipefail

[ "$(id -u)" -ne 0 ] || { echo "Run as a normal user, not root."; exit 1; }
APK="${1:-}"
[ -n "$APK" ] && [ -f "$APK" ] || { echo "Usage: $0 path/to/app.apk"; exit 1; }

MOBSF_DIR="$HOME/tools/MobSF"
HOST="127.0.0.1:8000"
OUT_ROOT="$HOME/mobsf-out"
PY="$(command -v python3.13 || command -v python3.12 || true)"

api_key() {
  "$PY" - <<'PYEOF'
from hashlib import sha256
import os
s = os.path.expanduser("~/.MobSF/secret")
print(sha256(open(s, "rb").read().strip()).hexdigest())
PYEOF
}

# Start MobSF only if nothing answers on the port yet.
if ! curl -s -o /dev/null "http://$HOST/"; then
  echo "[*] Starting MobSF (static only, no emulator)"
  ( cd "$MOBSF_DIR" && [ -n "$PY" ] && python3 -m poetry env use "$PY" >/dev/null 2>&1
    setsid nohup ./run.sh "$HOST" >/tmp/mobsf-static.log 2>&1 </dev/null & )
  for _ in $(seq 1 40); do curl -s -o /dev/null "http://$HOST/" && break; sleep 2; done
  curl -s -o /dev/null "http://$HOST/" || { echo "MobSF did not start, see /tmp/mobsf-static.log"; exit 1; }
fi

KEY="$(api_key)"
AUTH="Authorization: $KEY"
API="http://$HOST/api/v1"

echo "[*] Uploading $(basename "$APK")"
UP="$(curl -s -H "$AUTH" -F "file=@$APK" "$API/upload")"
HASH="$(printf '%s' "$UP" | jq -r '.hash // empty')"
[ -n "$HASH" ] || { echo "Upload failed: $UP"; exit 1; }

echo "[*] Scanning (this runs the full static analysis)"
curl -s -H "$AUTH" -X POST --data "hash=$HASH" "$API/scan" >/dev/null

OUT="$OUT_ROOT/$(basename "$APK" .apk)-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUT"
curl -s -H "$AUTH" -X POST --data "hash=$HASH" "$API/report_json" -o "$OUT/report.json"
curl -s -H "$AUTH" -X POST --data "hash=$HASH" "$API/download_pdf" -o "$OUT/report.pdf"

echo
echo "================ STATIC ANALYSIS SUMMARY ================"
"$PY" - "$OUT/report.json" <<'PYEOF'
import json, sys
r = json.load(open(sys.argv[1]))
a = r.get("appsec", {})
print(f"App          : {r.get('app_name')}  {r.get('version_name','')}")
print(f"Package      : {r.get('package_name')}")
print(f"SDK          : min {r.get('min_sdk')}  target {r.get('target_sdk')}")
print(f"Security score: {a.get('security_score')}/100   trackers: {a.get('total_trackers')}")
for level in ("high", "warning"):
    items = a.get(level, [])
    if not items:
        continue
    print(f"\n--- {level.upper()} ({len(items)}) ---")
    for it in items:
        print(f"  [{it.get('section','')}] {it.get('title','').strip()}")
print("\nExported components:",
      "activities", len(r.get("exported_activities", []) or []),
      "| providers", len(r.get("providers", []) or []))
fb = r.get("firebase_urls") or []
if fb:
    print("Firebase URLs:", len(fb))
PYEOF
echo "========================================================"
echo "Full JSON : $OUT/report.json"
echo "PDF report: $OUT/report.pdf"
echo "Web UI    : http://$HOST  (login mobsf/mobsf)"
