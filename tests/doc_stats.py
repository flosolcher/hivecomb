#!/usr/bin/env python3
"""Verify that the numbers the documentation states about this project are true.

    python3 tests/doc_stats.py

Every document here quotes counts — how many tests, how many lines, how many
operations. They were accurate when written and then the code moved. Audited on
2026-08-24, the same fact appeared with four different values:

    292 unit tests   CHANGELOG.md, CONTRIBUTING.md
    295 unit tests   README.md, twice
    305 tests        COMPARISON.md
    337              what `cargo test` actually reported

None of those were lies; each was true on the day it was typed. That is exactly
what makes the problem hard to notice by reading, and it is worse than untidy:
these numbers sit next to comparisons with other people's projects, where being
carelessly wrong about our own figures is not a good look and being carelessly
wrong about theirs would be worse.

So the numbers are checked rather than trusted.

# What this deliberately does not do

It does not touch *historical* claims — "on 2026-08-22 the oracle found four
defects that 292 unit tests had missed" is a statement about that day and stays
pinned to it. Only present-tense claims are checked. Where a document states a
number as current fact, it is listed below; where it states one as history, it
carries its date and is left alone.

# The failure this check must not have

A check that looks for a pattern and silently passes when the pattern is gone is
not a check — deleting the line would "fix" the failure. So a missing pattern is
a failure here, with its own message, and every entry below must match exactly
once.
"""

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def cargo_test_count(args):
    """Total tests reported by `cargo test`, summed over its result lines."""
    proc = subprocess.run(
        ["cargo", "test", *args],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        raise SystemExit(
            f"cargo test {' '.join(args)} failed, so its count cannot be trusted:\n"
            + proc.stdout[-2000:]
            + proc.stderr[-2000:]
        )
    counts = [
        int(m.group(1))
        for m in re.finditer(r"^test result: ok\. (\d+) passed", proc.stdout, re.M)
    ]
    if not counts:
        raise SystemExit("cargo test printed no result lines; the parser is wrong")
    return sum(counts)


def rust_source_lines():
    return sum(
        len(p.read_text(encoding="utf-8").splitlines())
        for p in (ROOT / "hivecomb" / "src").rglob("*.rs")
    )


def main():
    print("measuring what is actually true ...")
    lib = cargo_test_count(["-p", "hivecomb", "--all-features", "--lib"])
    fixtures = cargo_test_count(
        ["-p", "hivecomb", "--all-features", "--test", "live_fixtures"]
    )
    workspace = cargo_test_count(["--workspace", "--all-features"])
    lines = rust_source_lines()
    print(f"  hivecomb lib tests      {lib}")
    print(f"  live-node fixtures      {fixtures}")
    print(f"  workspace, all features {workspace}")
    print(f"  hivecomb/src lines      {lines}\n")

    # (file, regex with one capturing group, expected value, what it claims)
    #
    # The regex must match exactly once. Anchor each on enough surrounding text
    # that it cannot drift onto a different number in the same file.
    checks = [
        (
            "README.md",
            r"cargo test --all-features\s+# (\d+) unit tests",
            lib,
            "the unit-test count in the build instructions",
        ),
        (
            "README.md",
            r"# \d+ unit tests \+ (\d+) live-node fixtures",
            fixtures,
            "the live-node fixture count in the build instructions",
        ),
        (
            "COMPARISON.md",
            r"\| Tests \| [\d,]+ \| ([\d,]+) \|",
            workspace,
            "the test count in the xylem comparison table",
        ),
        (
            "COMPARISON.md",
            r"\| Rust source \| [\d,]+ lines \| ([\d,]+) lines \|",
            lines,
            "the source-line count in the xylem comparison table",
        ),
    ]

    failures = []
    for filename, pattern, expected, what in checks:
        text = (ROOT / filename).read_text(encoding="utf-8")
        found = re.findall(pattern, text)
        if len(found) != 1:
            failures.append(
                f"{filename}: {what} — expected exactly one match for /{pattern}/, "
                f"found {len(found)}. If the line was reworded, update this check; "
                f"if it was deleted, delete this check. Do not leave it unmatched, "
                f"because an unmatched pattern is a check that cannot fail."
            )
            continue
        actual = int(found[0].replace(",", ""))
        if actual != expected:
            failures.append(
                f"{filename}: {what} says {actual:,}, but it is {expected:,}"
            )
        else:
            print(f"  ok  {filename}: {what} = {actual:,}")

    if failures:
        print("\nthe documentation disagrees with the code:\n")
        for f in failures:
            print(f"  FAIL  {f}")
        print(
            "\nUpdate the document, not this check — unless the check is what is "
            "wrong, in which case say so in the commit."
        )
        return 1

    print(f"\n{len(checks)} documented figures, all of them true")
    return 0


if __name__ == "__main__":
    sys.exit(main())
