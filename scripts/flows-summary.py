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

hosts = set()
secrets = []

with open(sys.argv[1], "rb") as fh:
    for flow in FlowReader(fh).stream():
        req = getattr(flow, "request", None)
        if req is None:
            continue
        hosts.add(f"{req.scheme}://{req.host}")
        blobs = [req.pretty_url]
        if req.content:
            blobs.append(req.get_text(strict=False) or "")
        resp = getattr(flow, "response", None)
        if resp is not None and resp.content:
            blobs.append(resp.get_text(strict=False) or "")
        for blob in blobs:
            for line in blob.splitlines():
                if SECRET.search(line):
                    secrets.append(f"{req.host}: {line.strip()[:140]}")

print("--- Network: hosts contacted ---")
for h in sorted(hosts):
    mark = "  [!] CLEARTEXT " if h.startswith("http://") else "  "
    print(mark + h)

print("\n--- Possible secrets in captured traffic ---")
if secrets:
    for s in secrets[:15]:
        print("  " + s)
else:
    print("  none found by pattern (still review traffic.flows by hand)")
