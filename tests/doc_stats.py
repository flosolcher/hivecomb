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


def slug(heading):
    """GitHub's anchor for a heading: lowercase, punctuation dropped, spaces hyphened."""
    text = heading.lstrip("#").strip()
    kept = "".join(c for c in text.lower() if c.isalnum() or c in " -_")
    return kept.strip().replace(" ", "-")


def check_links(files):
    """Every local link and anchor in the documentation resolves.

    The comparison documents cross-reference each other heavily -- a claim about
    another project is supposed to link to its evidence -- so a link that quietly
    404s is the same class of defect as a number that quietly drifted.
    """
    import re as _re

    anchors = {}
    for name in files:
        text = (ROOT / name).read_text(encoding="utf-8")
        found = {slug(line) for line in text.splitlines() if line.startswith("#")}
        # Explicit anchors too. SECURITY_FINDINGS.md numbers its findings and refers
        # to them as `[14](#14)`, which no heading slug will ever produce, so each
        # carries an <a id="14"> of its own.
        found |= set(_re.findall(r'<a\s+(?:id|name)="([^"]+)"', text))
        anchors[name] = found

    problems = []
    for name in files:
        text = (ROOT / name).read_text(encoding="utf-8")
        for label, target in _re.findall(r"\[([^\]]+)\]\(([^)]+)\)", text):
            if target.startswith(("http://", "https://", "mailto:")):
                continue
            path, _, anchor = target.partition("#")
            if path:
                dest = (ROOT / name).parent / path
                if not dest.exists():
                    problems.append(f"{name}: [{label}] -> {target} (no such file)")
                    continue
                key = str(dest.resolve().relative_to(ROOT))
            else:
                key = name
            if anchor and key in anchors and anchor not in anchors[key]:
                problems.append(f"{name}: [{label}] -> {target} (no such heading)")
    return problems


def check_tables_agree():
    """The beem speed table appears in two READMEs. They must not drift apart.

    Keeping one copy would be tidier, but python/README.md is the PyPI long
    description for `hivecomb-beem` and has to stand on its own there. So both
    stay, and the duplication is made unable to rot instead of being argued about.
    """
    import re as _re

    rows = {}
    for name in ("README.md", "python/README.md"):
        text = (ROOT / name).read_text(encoding="utf-8")
        rows[name] = dict(
            _re.findall(r"\| (sign a [^|]+|serialize and digest[^|]*) \| ([^|]+) \|", text)
        )
    a, b = rows["README.md"], rows["python/README.md"]
    shared = set(a) & set(b)
    if not shared:
        return [
            "README.md and python/README.md share no benchmark rows. Either the tables "
            "were reworded or this check is looking for the wrong thing -- an empty "
            "comparison is not a passing one."
        ]
    return [
        f"the '{k.strip()}' row differs: README says {a[k].strip()}, "
        f"python/README says {b[k].strip()}"
        for k in sorted(shared)
        if a[k].strip() != b[k].strip()
    ]


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

    DOCS = [
        "README.md",
        "COMPARISON.md",
        "MIGRATION.md",
        "SECURITY_FINDINGS.md",
        "CHANGELOG.md",
        "CREDITS.md",
        "CONTRIBUTING.md",
        "python/README.md",
    ]
    link_problems = check_links(DOCS)
    for problem in link_problems:
        failures.append(problem)
    if not link_problems:
        print(f"  ok  every local link and anchor across {len(DOCS)} documents resolves")

    # README summarises COMPARISON.md's xylem section by counting the things this
    # project took from it. That count was written as "five" above a list of six for
    # as long as the section has existed, in both files independently.
    took = len(re.findall(r"^#### \d+\. ", (ROOT / "COMPARISON.md").read_text(), re.M))
    words = {4: "four", 5: "five", 6: "six", 7: "seven", 8: "eight"}
    claimed = re.findall(r"(\w+) things from xylem", (ROOT / "README.md").read_text())
    if len(claimed) != 1:
        failures.append(
            "README.md: expected exactly one 'N things from xylem' claim, found "
            f"{len(claimed)} — reword the check if the sentence moved."
        )
    elif claimed[0] != words.get(took, str(took)):
        failures.append(
            f"README.md says '{claimed[0]} things from xylem' but COMPARISON.md lists "
            f"{took}"
        )
    else:
        print(f"  ok  README's summary of COMPARISON.md's xylem section = {took} items")

    table_problems = check_tables_agree()
    for problem in table_problems:
        failures.append(problem)
    if not table_problems:
        print("  ok  the beem benchmark table agrees between README.md and python/README.md")

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
