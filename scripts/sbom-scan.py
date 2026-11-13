#!/usr/bin/env python3
# sbom-scan.py: build a software bill of materials from an APK's bundled dependency markers
# and check every component against the live OSV.dev vulnerability database.
#
# Components come from markers the Android build embeds in the APK:
#   - META-INF/<group>_<artifact>.version  (AndroidX/Jetpack and others; content is the version)
#   - *.properties with version= / client=  (Google Play services, Firebase)
#
# Usage: scripts/sbom-scan.py path/to/app.apk [-o output_dir]
# Writes a CycloneDX SBOM (sbom.cdx.json) and prints risky dependencies, most severe first.
import argparse
import json
import re
import sys
import time
import urllib.request
import zipfile
from pathlib import Path

OSV_BATCH = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns/"

# Google artifacts carry no group in their .properties marker; map the well-known prefixes.
GROUP_BY_PREFIX = {
    "firebase-": "com.google.firebase",
    "play-services-": "com.google.android.gms",
    "transport-": "com.google.android.datatransport",
}
# .version markers whose name uses '_' both as separator and inside the name, so the
# group/artifact cannot be recovered by splitting. Map the known ones explicitly.
VERSION_REMAP = {
    "kotlinx_coroutines": "org.jetbrains.kotlinx",
}
SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MODERATE": 2, "MEDIUM": 2, "LOW": 1, "": 0}


def resolve_version_marker(coord, version):
    """Map a META-INF '<name>.version' marker to (group, artifact) or None if ambiguous.

    Trustworthy only when the group is a real reverse-DNS group (contains a dot),
    e.g. androidx.core_core -> androidx.core:core. Known underscore-named libraries
    are remapped; anything else is returned as unresolved so coverage stays honest.
    """
    if "_" not in coord:
        return None
    group, artifact = coord.rsplit("_", 1)
    if "." in group:
        return (group, artifact, version)
    for prefix, real_group in VERSION_REMAP.items():
        if coord.startswith(prefix):
            return (real_group, coord.replace("_", "-"), version)
    return None


def components_from_apk(apk_path):
    """Return (resolved, unresolved): resolved is [(group,artifact,version)] with trusted
    Maven coordinates; unresolved is [(marker, version)] that could not be mapped."""
    found = {}
    unresolved = []
    with zipfile.ZipFile(apk_path) as z:
        names = z.namelist()
        for name in names:
            if name.startswith("META-INF/") and name.endswith(".version"):
                coord = name[len("META-INF/"):-len(".version")]
                version = z.read(name).decode("utf-8", "replace").strip()
                if not version:
                    continue
                r = resolve_version_marker(coord, version)
                if r:
                    found[(r[0], r[1])] = r[2]
                else:
                    unresolved.append((coord, version))
        for name in names:
            if not name.endswith(".properties"):
                continue
            text = z.read(name).decode("utf-8", "replace")
            props = dict(re.findall(r"^([\w.-]+)=(.*)$", text, re.M))
            artifact = props.get("client")
            version = props.get("version")
            if not artifact or not version:
                continue
            group = next(
                (g for p, g in GROUP_BY_PREFIX.items() if artifact.startswith(p)), None
            )
            if group and (group, artifact) not in found:
                found[(group, artifact)] = version
    resolved = sorted((g, a, v) for (g, a), v in found.items())
    return resolved, sorted(set(unresolved))


def post_json(url, payload):
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode(), headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)


def get_json(url):
    with urllib.request.urlopen(url, timeout=30) as r:
        return json.load(r)


def query_osv(components):
    """Return {(group,artifact,version): [vuln_id,...]} for components with known vulns."""
    queries = [
        {"package": {"ecosystem": "Maven", "name": f"{g}:{a}"}, "version": v}
        for g, a, v in components
    ]
    hits = {}
    for start in range(0, len(queries), 500):
        chunk = queries[start:start + 500]
        res = post_json(OSV_BATCH, {"queries": chunk}).get("results", [])
        for comp, result in zip(components[start:start + 500], res):
            vulns = result.get("vulns") or []
            if vulns:
                hits[comp] = [v["id"] for v in vulns]
        time.sleep(0.2)
    return hits


def vuln_detail(vuln_id, cache):
    if vuln_id in cache:
        return cache[vuln_id]
    d = get_json(OSV_VULN + vuln_id)
    sev = (d.get("database_specific") or {}).get("severity", "") or ""
    cvss = next(
        (s["score"] for s in d.get("severity", []) if s.get("type", "").startswith("CVSS")),
        "",
    )
    detail = {
        "id": d.get("id"),
        "aliases": d.get("aliases", []),
        "summary": (d.get("summary") or "").strip(),
        "severity": sev.upper(),
        "cvss": cvss,
    }
    cache[vuln_id] = detail
    return detail


def write_sbom(components, hits, details, out_file):
    comps = []
    vulns = []
    for g, a, v in components:
        ref = f"pkg:maven/{g}/{a}@{v}"
        comps.append({
            "type": "library",
            "bom-ref": ref,
            "group": g,
            "name": a,
            "version": v,
            "purl": ref,
        })
        for vid in hits.get((g, a, v), []):
            d = details[vid]
            vulns.append({
                "bom-ref": vid,
                "id": d["id"],
                "source": {"name": "OSV", "url": OSV_VULN + d["id"]},
                "ratings": [{"severity": d["severity"].title() or "Unknown"}],
                "description": d["summary"],
                "affects": [{"ref": ref}],
            })
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "components": comps,
        "vulnerabilities": vulns,
    }
    out_file.write_text(json.dumps(sbom, indent=2))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("apk")
    ap.add_argument("-o", "--out", default=None)
    args = ap.parse_args()

    apk = Path(args.apk)
    if not apk.is_file():
        sys.exit(f"APK not found: {apk}")

    out_dir = Path(args.out) if args.out else (
        Path.home() / "mobsf-out" / f"sbom-{apk.stem}-{time.strftime('%Y%m%d-%H%M%S')}"
    )
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"[*] Reading dependency markers from {apk.name}")
    components, unresolved = components_from_apk(apk)
    print(f"[*] Found {len(components)} components with Maven coordinates"
          f" ({len(unresolved)} markers unresolved, not checked)")

    print("[*] Querying OSV.dev for known vulnerabilities (live)")
    hits = query_osv(components)

    details = {}
    for ids in hits.values():
        for vid in ids:
            vuln_detail(vid, details)

    sbom_file = out_dir / "sbom.cdx.json"
    write_sbom(components, hits, details, sbom_file)

    # Rank vulnerable components by the most severe vuln they carry.
    rows = []
    for comp, ids in hits.items():
        worst = max((details[i]["severity"] for i in ids), key=lambda s: SEV_RANK.get(s, 0))
        rows.append((SEV_RANK.get(worst, 0), worst, comp, ids))
    rows.sort(reverse=True)

    print("\n================ SBOM RISK SUMMARY ================")
    print(f"Components: {len(components)}   Vulnerable: {len(hits)}")
    if not rows:
        print("No known vulnerabilities in OSV for the detected components.")
    for _, worst, (g, a, v), ids in rows:
        print(f"\n[{worst or 'UNKNOWN'}] {g}:{a} {v}")
        for vid in ids:
            d = details[vid]
            cve = ", ".join(d["aliases"]) or d["id"]
            print(f"    {cve}  ({d['severity'] or 'n/a'})  {d['summary'][:90]}")
    if unresolved:
        print(f"\n--- {len(unresolved)} unresolved markers (no reliable Maven coordinate, "
              "not checked against OSV) ---")
        for marker, version in unresolved:
            print(f"    {marker}  {version}")
    print("==================================================")
    print(f"CycloneDX SBOM: {sbom_file}")


if __name__ == "__main__":
    main()
