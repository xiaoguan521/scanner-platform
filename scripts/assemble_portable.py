#!/usr/bin/env python3
"""Assemble the sec-portable package layout (docs/portable.md); never scans.

    sec-portable(.exe)  bin/  vuln-data/  config/trusted-rule-keys/
    runtime/inputs/  README.md  docs/  tools/  start-* and prepare-data-* scripts

The binary must already embed the web UI (built with `make portable` or the
release workflow). vuln-data/ is left empty: prepare it with
`sec-portable prepare` or the offline vulnerability data package.
"""

import argparse
import os
import shutil
import sys

DOCS = ["portable.md", "engines.md", "ssh-collection.md", "linux-server-scan.md", "offline-vulnerability-data.md"]
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--binary", required=True, help="compiled sec-portable or sec-portable.exe")
    parser.add_argument("--engines", required=True, help="directory with nuclei, trivy and their .installed.json files")
    parser.add_argument("--output", required=True, help="package directory to create (must not exist)")
    parser.add_argument("--os", choices=["linux", "darwin", "windows"], help="target OS for the one-click scripts (default: from the binary name)")
    args = parser.parse_args()

    if os.path.exists(args.output):
        raise SystemExit(f"{args.output} already exists; refusing to overwrite")
    windows = args.binary.endswith(".exe")
    for engine in ("nuclei", "trivy"):
        name = engine + (".exe" if windows else "")
        if not os.path.isfile(os.path.join(args.engines, name)):
            raise SystemExit(f"{name} missing from {args.engines}")

    os.makedirs(args.output)
    shutil.copy2(args.binary, os.path.join(args.output, "sec-portable.exe" if windows else "sec-portable"))
    shutil.copytree(args.engines, os.path.join(args.output, "bin"), symlinks=False)
    for directory in ("vuln-data", os.path.join("config", "trusted-rule-keys"), os.path.join("runtime", "inputs")):
        os.makedirs(os.path.join(args.output, directory))
    shutil.copy2(os.path.join(ROOT, "docs", "portable.md"), os.path.join(args.output, "README.md"))
    os.makedirs(os.path.join(args.output, "docs"))
    for name in DOCS:
        shutil.copy2(os.path.join(ROOT, "docs", name), os.path.join(args.output, "docs", name))
    # One-click start and data-preparation scripts for the target OS.
    target = args.os or ("windows" if windows else None)
    suffixes = {"windows": ["-windows.bat"], "darwin": ["-macos.command"], "linux": ["-linux.sh"]}
    wanted = suffixes[target] if target else suffixes["darwin"] + suffixes["linux"]
    for name in sorted(os.listdir(os.path.join(ROOT, "scripts", "portable"))):
        if any(name.endswith(suffix) for suffix in wanted):
            shutil.copy2(os.path.join(ROOT, "scripts", "portable", name), os.path.join(args.output, name))
    os.makedirs(os.path.join(args.output, "tools"))
    shutil.copy2(os.path.join(ROOT, "scripts", "collect_linux_inputs.py"), os.path.join(args.output, "tools"))
    print("assembled", args.output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
