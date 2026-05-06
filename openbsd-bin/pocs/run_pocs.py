#!/usr/bin/env python3
"""
Run every per-finding PoC script in audit-findings/pocs/.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def main() -> int:
    pocs_dir = Path(__file__).resolve().parent
    scripts = sorted(pocs_dir.glob("poc_[0-9][0-9][0-9].py"))
    failures = 0

    for script in scripts:
        proc = subprocess.run([sys.executable, str(script)], text=True)
        if proc.returncode:
            failures += 1

    passed = len(scripts) - failures
    print(f"\n{passed} passed, {failures} failed")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())

