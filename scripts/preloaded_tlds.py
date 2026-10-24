#!/usr/bin/env python3
"""Extract TLDs from a separately downloaded, pinned Chromium preload file.
Usage: preloaded_tlds.py SOURCE COMMIT OUTPUT
No network requests; filters match docs/spec/web-collector.md, Preloaded TLDs.
"""
import json
import pathlib
import re
import sys
source, commit, output = sys.argv[1:]
if not re.fullmatch(r"[0-9a-f]{40}", commit):
    raise SystemExit("commit must be a full SHA")
data = pathlib.Path(source).read_text()
entries = json.loads(re.sub(r"^\s*//.*$", "", data, flags=re.M))["entries"]
names = sorted(e["name"] for e in entries if "." not in e["name"]
               and e.get("mode") == "force-https" and e.get("include_subdomains")
               and e.get("policy") != "test")
pathlib.Path(output).write_text(f"# Chromium commit {commit}\n# Version 2026-10-09.1\n"
                              + "\n".join(names) + "\n")
