#!/usr/bin/env python3
# report.py: merge the latest static, SBOM and dynamic outputs under ~/mobsf-out into one
# report (Markdown by default, self-contained HTML with --html). Run after the scan scripts.
# This is a working draft for a human to verify, not a finished deliverable.
#
# Usage: scripts/report.py [--match SUBSTR] [--html] [-o OUTFILE]
import argparse
import base64
import html
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


def webview_findings(md5):
    """Run webview-check.sh on the MobSF-cached APK and parse its output. One source of
    truth for the WebView rules; returns [(sev, note, [file:line, ...])]."""
    here = Path(__file__).resolve().parent
    script = here / "webview-check.sh"
    apk = Path.home() / ".MobSF" / "uploads" / md5 / f"{md5}.apk"
    if not (script.exists() and apk.exists()):
        return []
    import subprocess
    try:
        out = subprocess.run(["bash", str(script), str(apk)],
                             capture_output=True, text=True, timeout=300).stdout
    except Exception:
        return []
    findings, cur = [], None
    for line in out.splitlines():
        m = re.match(r"\[(HIGH|WARN|INFO)\]\s+(.*)", line.strip())
        if m:
            cur = {"sev": m.group(1), "note": m.group(2), "locations": []}
            findings.append(cur)
        elif cur is not None and line.strip() and line.startswith("    "):
            cur["locations"].append(line.strip())
    return [f for f in findings if f["locations"]]


def gather(match):
    """Collect facts from the latest outputs into one dict the renderers consume."""
    static = latest("", "report.json", match)
    sbom = latest("sbom-", "sbom.cdx.json", match)
    dyn = latest("dyn-", "traffic.flows", match)
    if not any((static, sbom, dyn)):
        sys.exit("No scan outputs found under ~/mobsf-out (run the scan scripts first).")

    data = {"generated": time.strftime("%Y-%m-%d %H:%M"),
            "app": None, "static": None, "webview": None, "sbom": None, "dynamic": None}

    if static:
        r = json.load(open(static / "report.json"))
        a = r.get("appsec", {})
        if r.get("md5"):
            wv = webview_findings(r["md5"])
            if wv:
                data["webview"] = wv
        data["app"] = {
            "name": f"{r.get('app_name')} {r.get('version_name','')}".strip(),
            "package": r.get("package_name"),
            "sdk": f"min {r.get('min_sdk')}, target {r.get('target_sdk')}",
            "score": a.get("security_score"),
            "trackers": a.get("total_trackers"),
            "exported_act": len(r.get("exported_activities") or []),
            "exported_prov": len(r.get("providers") or []),
        }
        data["static"] = {
            "high": [(i.get("section", ""), i.get("title", "").strip()) for i in a.get("high", [])],
            "warning": [(i.get("section", ""), i.get("title", "").strip()) for i in a.get("warning", [])],
        }

    if sbom:
        s = json.load(open(sbom / "sbom.cdx.json"))
        vulns = []
        for v in s.get("vulnerabilities", []):
            vulns.append({
                "sev": (v.get("ratings") or [{}])[0].get("severity", "?"),
                "id": v.get("id"),
                "ref": (v.get("affects") or [{}])[0].get("ref", ""),
            })
        data["sbom"] = {"components": len(s.get("components", [])), "vulns": vulns}

    if dyn:
        hosts, cleartext, app_secrets, fw = read_flows(dyn / "traffic.flows")
        shot = dyn / "screen.png"
        data["dynamic"] = {
            "hosts": hosts, "cleartext": cleartext, "app_secrets": app_secrets,
            "fw": fw, "evidence": str(dyn),
            "screenshot": str(shot) if shot.exists() else None,
        }
    return data


def render_markdown(d):
    out = ["# Android pentest report\n",
           f"_Generated {d['generated']} — working draft, verify every finding by hand._\n"]
    a = d["app"]
    if a:
        out += ["## App\n",
                f"- **Name:** {a['name']}", f"- **Package:** `{a['package']}`",
                f"- **SDK:** {a['sdk']}", f"- **MobSF security score:** {a['score']}/100",
                f"- **Trackers:** {a['trackers']}",
                f"- **Exported:** {a['exported_act']} activities, {a['exported_prov']} providers\n"]
    if d["static"]:
        out.append("## Static findings\n")
        for level in ("high", "warning"):
            items = d["static"][level]
            if items:
                out.append(f"### {level.title()} ({len(items)})")
                out += [f"- [{sec}] {title}" for sec, title in items]
                out.append("")
    if d["webview"]:
        out.append("## WebView configuration\n")
        for f in d["webview"]:
            out.append(f"- **[{f['sev']}]** {f['note']}")
            out += [f"    - `{loc}`" for loc in f["locations"]]
        out.append("")
    if d["sbom"]:
        s = d["sbom"]
        out += ["## Dependencies (SBOM / OSV)\n",
                f"- Components: {s['components']}", f"- Known-vulnerable: {len(s['vulns'])}"]
        out += [f"  - [{v['sev']}] {v['id']} — {v['ref']}" for v in s["vulns"]]
        out.append("")
    if d["dynamic"]:
        n = d["dynamic"]
        out += ["## Dynamic (network)\n", f"- Hosts contacted: {len(n['hosts'])}"]
        if n["cleartext"]:
            out.append(f"- **Cleartext HTTP:** {', '.join(n['cleartext'])}")
        out.append(f"- First-party secret matches: {len(n['app_secrets'])} "
                   f"(+{n['fw']} on Google/analytics hosts, framework noise)")
        out += [f"  - {s}" for s in n["app_secrets"][:15]]
        out.append(f"\n- Evidence: `{n['evidence']}`")
    return "\n".join(out)


def _sev_class(sev):
    s = (sev or "").lower()
    return "high" if s in ("high", "critical") else "warn" if s in ("warn", "warning", "moderate", "medium") else "info"


def render_html(d):
    e = html.escape
    rows = []
    a = d["app"]
    head = f"{e(a['name'])}" if a else "Android pentest report"
    rows.append(f"<header><h1>Android pentest report</h1>"
                f"<p class=draft>Generated {d['generated']} — working draft, verify every finding by hand.</p></header>")
    if a:
        score = a["score"] or 0
        sc = "high" if score < 40 else "warn" if score < 70 else "info"
        rows.append("<section><h2>App</h2><table class=kv>"
                    f"<tr><td>Name</td><td>{e(a['name'])}</td></tr>"
                    f"<tr><td>Package</td><td><code>{e(a['package'] or '')}</code></td></tr>"
                    f"<tr><td>SDK</td><td>{e(a['sdk'])}</td></tr>"
                    f"<tr><td>Security score</td><td><span class='badge {sc}'>{score}/100</span></td></tr>"
                    f"<tr><td>Trackers</td><td>{a['trackers']}</td></tr>"
                    f"<tr><td>Exported</td><td>{a['exported_act']} activities, {a['exported_prov']} providers</td></tr>"
                    "</table></section>")
    if d["static"]:
        rows.append("<section><h2>Static findings</h2>")
        for level in ("high", "warning"):
            items = d["static"][level]
            if not items:
                continue
            cls = "high" if level == "high" else "warn"
            rows.append(f"<h3><span class='badge {cls}'>{level.title()}</span> {len(items)}</h3><ul>")
            rows += [f"<li><span class=sec>{e(sec)}</span> {e(title)}</li>" for sec, title in items]
            rows.append("</ul>")
        rows.append("</section>")
    if d["webview"]:
        rows.append("<section><h2>WebView configuration</h2><ul>")
        for f in d["webview"]:
            locs = ", ".join(f"<code>{e(loc)}</code>" for loc in f["locations"])
            rows.append(f"<li><span class='badge {_sev_class(f['sev'])}'>{e(f['sev'])}</span> "
                        f"{e(f['note'])} — {locs}</li>")
        rows.append("</ul></section>")
    if d["sbom"]:
        s = d["sbom"]
        rows.append(f"<section><h2>Dependencies (SBOM / OSV)</h2>"
                    f"<p>Components: <b>{s['components']}</b> · Known-vulnerable: <b>{len(s['vulns'])}</b></p>")
        if s["vulns"]:
            rows.append("<ul>")
            rows += [f"<li><span class='badge {_sev_class(v['sev'])}'>{e(v['sev'])}</span> "
                     f"{e(v['id'])} — <code>{e(v['ref'])}</code></li>" for v in s["vulns"]]
            rows.append("</ul>")
        rows.append("</section>")
    if d["dynamic"]:
        n = d["dynamic"]
        rows.append(f"<section><h2>Dynamic (network)</h2><p>Hosts contacted: <b>{len(n['hosts'])}</b></p>")
        if n["cleartext"]:
            rows.append("<p>Cleartext HTTP: " +
                        " ".join(f"<span class='badge high'>{e(h)}</span>" for h in n["cleartext"]) + "</p>")
        rows.append(f"<p>First-party secret matches: <b>{len(n['app_secrets'])}</b> "
                    f"(+{n['fw']} on Google/analytics hosts, framework noise)</p>")
        if n["app_secrets"]:
            rows.append("<ul>" + "".join(f"<li><code>{e(s)}</code></li>" for s in n["app_secrets"][:15]) + "</ul>")
        rows.append("<details><summary>Hosts contacted</summary><ul>" +
                    "".join(f"<li>{e(h)}</li>" for h in n["hosts"]) + "</ul></details>")
        if n["screenshot"]:
            b64 = base64.b64encode(Path(n["screenshot"]).read_bytes()).decode()
            rows.append(f"<details><summary>Screenshot</summary><img alt=screenshot "
                        f"src='data:image/png;base64,{b64}'></details>")
        rows.append(f"<p class=evidence>Evidence: <code>{e(n['evidence'])}</code></p></section>")

    css = """
    :root{color-scheme:light dark}
    body{font:15px/1.5 system-ui,sans-serif;max-width:900px;margin:2rem auto;padding:0 1rem;color:#1a1a1a}
    @media(prefers-color-scheme:dark){body{background:#15171a;color:#e6e6e6}code{color:#9cd}}
    h1{margin:0 0 .2rem} .draft{color:#b36b00;font-size:.9rem;margin-top:0}
    section{border-top:1px solid #8884;padding:.5rem 0 1rem}
    table.kv td{padding:.2rem .6rem .2rem 0} table.kv td:first-child{color:#888;white-space:nowrap}
    .badge{display:inline-block;padding:.05rem .5rem;border-radius:.6rem;font-size:.8rem;font-weight:600;color:#fff}
    .badge.high{background:#c0392b} .badge.warn{background:#c98a00} .badge.info{background:#2d7d46}
    .sec{color:#888;font-size:.8rem;margin-right:.3rem} ul{margin:.3rem 0}
    code{background:#8882;padding:.05rem .3rem;border-radius:.3rem;font-size:.85em}
    img{max-width:320px;border:1px solid #8884;border-radius:.4rem;margin-top:.5rem}
    summary{cursor:pointer;color:#4a90d9} .evidence{color:#888;font-size:.85rem}
    """
    return (f"<!doctype html><html lang=en><head><meta charset=utf-8>"
            f"<meta name=viewport content='width=device-width,initial-scale=1'>"
            f"<title>Pentest report — {e(head)}</title><style>{css}</style></head>"
            f"<body>{''.join(rows)}</body></html>")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--match", default="")
    ap.add_argument("--html", action="store_true", help="write self-contained HTML instead of Markdown")
    ap.add_argument("-o", "--out", default=None)
    args = ap.parse_args()

    data = gather(args.match)
    ext = "html" if args.html else "md"
    text = render_html(data) if args.html else render_markdown(data)

    out_file = Path(args.out) if args.out else (
        OUT_ROOT / f"report-{args.match or 'latest'}-{time.strftime('%Y%m%d-%H%M%S')}.{ext}")
    out_file.write_text(text)
    if not args.html:
        print(text)
    print(f"\n[written] {out_file}")


if __name__ == "__main__":
    main()
