#!/usr/bin/env python3
# report.py: merge the latest static, SBOM and dynamic outputs under ~/mobsf-out into one
# short Markdown report. Run after the scan scripts. This is a working draft for a human to
# verify, not a finished deliverable.
#
# Usage: scripts/report.py [--match SUBSTR] [-o report.md]
import argparse
import json
import re
import sys
import time
from pathlib import Path

OUT_ROOT = Path.home() / "mobsf-out"
SECRET = re.compile(
    r"password|passwd|pwd|token|secret|api[_-]?key|authorization|bearer|session|jwt|refresh", re.I)
FRAMEWORK = ("googleapis.com", "gstatic.com", "google.com", "googleadservices.com",
             "doubleclick.net", "gvt1.com", "app-measurement.com", "crashlytics.com",
             "youtube.com", "googlesyndication.com", "android.clients.google.com")


def latest(prefix, must_contain, match):
    """Most recent output dir whose name starts with prefix, holds must_contain, matches filter."""
    cands = [
        d for d in OUT_ROOT.glob(prefix + "*")
        if d.is_dir() and (d / must_contain).exists() and (match in d.name)
    ]
    return max(cands, key=lambda d: d.stat().st_mtime, default=None)


def read_flows(flows_path):
    from mitmproxy.io import FlowReader
    hosts, cleartext, app_secrets, fw = set(), set(), [], 0
    with open(flows_path, "rb") as fh:
        for flow in FlowReader(fh).stream():
            req = getattr(flow, "request", None)
            if req is None:
                continue
            hosts.add(req.host)
            if req.scheme == "http":
                cleartext.add(req.host)
            is_fw = any(req.host == d or req.host.endswith("." + d) for d in FRAMEWORK)
            blobs = [req.pretty_url]
            for h in ("authorization", "cookie", "x-api-key"):
                if h in req.headers:
                    blobs.append(f"{h}: {req.headers[h]}")
            if req.content:
                blobs.append(req.get_text(strict=False) or "")
            resp = getattr(flow, "response", None)
            if resp is not None and resp.content:
                blobs.append(resp.get_text(strict=False) or "")
            for blob in blobs:
                for line in blob.splitlines():
                    if SECRET.search(line):
                        if is_fw:
                            fw += 1
                        else:
                            app_secrets.append(f"{req.host}: {line.strip()[:120]}")
    return sorted(hosts), sorted(cleartext), app_secrets, fw


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--match", default="")
    ap.add_argument("-o", "--out", default=None)
    args = ap.parse_args()

    static = latest("", "report.json", args.match)
    # The static dir has no prefix, so exclude the sbom-/dyn- ones that also lack report.json anyway.
    sbom = latest("sbom-", "sbom.cdx.json", args.match)
    dyn = latest("dyn-", "traffic.flows", args.match)
    if not any((static, sbom, dyn)):
        sys.exit("No scan outputs found under ~/mobsf-out (run the scan scripts first).")

    out = []
    w = out.append
    w(f"# Android pentest report\n")
    w(f"_Generated {time.strftime('%Y-%m-%d %H:%M')} — working draft, verify every finding by hand._\n")

    if static:
        r = json.load(open(static / "report.json"))
        a = r.get("appsec", {})
        w("## App\n")
        w(f"- **Name:** {r.get('app_name')} {r.get('version_name','')}")
        w(f"- **Package:** `{r.get('package_name')}`")
        w(f"- **SDK:** min {r.get('min_sdk')}, target {r.get('target_sdk')}")
        w(f"- **MobSF security score:** {a.get('security_score')}/100")
        w(f"- **Trackers:** {a.get('total_trackers')}")
        w(f"- **Exported:** {len(r.get('exported_activities') or [])} activities, "
          f"{len(r.get('providers') or [])} providers\n")
        w("## Static findings\n")
        for level in ("high", "warning"):
            items = a.get(level, [])
            if items:
                w(f"### {level.title()} ({len(items)})")
                for it in items:
                    w(f"- [{it.get('section','')}] {it.get('title','').strip()}")
                w("")

    if sbom:
        s = json.load(open(sbom / "sbom.cdx.json"))
        vulns = s.get("vulnerabilities", [])
        w("## Dependencies (SBOM / OSV)\n")
        w(f"- Components: {len(s.get('components', []))}")
        w(f"- Known-vulnerable: {len(vulns)}")
        for v in vulns:
            sev = (v.get("ratings") or [{}])[0].get("severity", "?")
            aff = (v.get("affects") or [{}])[0].get("ref", "")
            w(f"  - [{sev}] {v.get('id')} — {aff}")
        w("")

    if dyn:
        hosts, cleartext, app_secrets, fw = read_flows(dyn / "traffic.flows")
        w("## Dynamic (network)\n")
        w(f"- Hosts contacted: {len(hosts)}")
        if cleartext:
            w(f"- **Cleartext HTTP:** {', '.join(cleartext)}")
        w(f"- First-party secret matches: {len(app_secrets)} "
          f"(+{fw} on Google/analytics hosts, framework noise)")
        for s in app_secrets[:15]:
            w(f"  - {s}")
        w(f"\n- Evidence: `{dyn}` (traffic.flows, appdata.tar, logcat.txt, screen.png)\n")

    text = "\n".join(out)
    out_file = Path(args.out) if args.out else (
        OUT_ROOT / f"report-{args.match or 'latest'}-{time.strftime('%Y%m%d-%H%M%S')}.md")
    out_file.write_text(text)
    print(text)
    print(f"\n[written] {out_file}")


if __name__ == "__main__":
    main()
