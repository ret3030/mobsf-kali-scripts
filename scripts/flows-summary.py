#!/usr/bin/env python3
# flows-summary.py: read a mitmproxy .flows file and print hosts and likely secrets.
# Usage: python3 flows-summary.py traffic.flows
import re
import sys

from mitmproxy.io import FlowReader

SECRET = re.compile(
    r"password|passwd|pwd|token|secret|api[_-]?key|authorization|bearer|session|jwt|refresh",
    re.I,
)
# Google/analytics infrastructure dumps its own config and keys; that noise drowns the app's
# traffic in the secret scan. Secrets from these hosts are counted, not listed in full.
FRAMEWORK = (
    "googleapis.com", "gstatic.com", "google.com", "googleadservices.com",
    "doubleclick.net", "gvt1.com", "app-measurement.com", "crashlytics.com",
    "youtube.com", "googlesyndication.com", "android.clients.google.com",
)


def is_framework(host):
    return any(host == d or host.endswith("." + d) for d in FRAMEWORK)


hosts = set()
app_secrets = []
framework_secret_count = 0

with open(sys.argv[1], "rb") as fh:
    for flow in FlowReader(fh).stream():
        req = getattr(flow, "request", None)
        if req is None:
            continue
        hosts.add(f"{req.scheme}://{req.host}")
        blobs = [req.pretty_url]
        for header in ("authorization", "cookie", "x-api-key"):
            if header in req.headers:
                blobs.append(f"{header}: {req.headers[header]}")
        if req.content:
            blobs.append(req.get_text(strict=False) or "")
        resp = getattr(flow, "response", None)
        if resp is not None and resp.content:
            blobs.append(resp.get_text(strict=False) or "")
        for blob in blobs:
            for line in blob.splitlines():
                if SECRET.search(line):
                    if is_framework(req.host):
                        framework_secret_count += 1
                    else:
                        app_secrets.append(f"{req.host}: {line.strip()[:140]}")

print("--- Network: hosts contacted ---")
for h in sorted(hosts):
    mark = "  [!] CLEARTEXT " if h.startswith("http://") else "  "
    print(mark + h)

print("\n--- Possible secrets in first-party traffic (non-Google hosts) ---")
if app_secrets:
    for s in app_secrets[:25]:
        print("  " + s)
else:
    print("  none found by pattern (still review traffic.flows by hand)")
if framework_secret_count:
    print(f"  (+{framework_secret_count} matches on Google/analytics hosts, not shown; "
          "these are framework config, rarely the app's own secrets)")
