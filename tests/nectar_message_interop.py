#!/usr/bin/env python3
"""Check this project's signed-message envelope against hive-nectar's.

    PYTHONPATH=python <python with hive-nectar and hivecomb> tests/nectar_message_interop.py

COMPARISON.md states that the `Message` envelope here matches
[hive-nectar](https://github.com/srbde/hive-nectar)'s. This is that statement,
checked against nectar rather than reasoned about. It exists because the table it
appears in makes claims about someone else's project, and this project has already
published one finding about someone else's project that turned out to be wrong
(SECURITY_FINDINGS.md finding 8, retracted).

# V1: three constants, and they decide interoperability

The V1 format is an encapsulated text block. How it is split, what metadata is
hashed, and the wrapper text are three class constants, and a single byte of
difference in any of them means a message signed by one library does not verify
under the other. Those are compared directly.

# V2: not those constants, and a divergence worth naming

`MessageV2` is a JSON payload rather than a text envelope, and **neither** library
defines the V1 constants on it. An earlier version of this check compared them
anyway and reported "identical" — because `None == None`. That is a check that
cannot fail, which this repository treats as worse than no check, so V2 is
compared on what it actually does.

The payload is the same list in the same order, dumped with the same separators.
One field differs: nectar stamps `str(datetime.now(timezone.utc))`, which renders
a `+00:00` offset, where beem used a naive `utcnow()` and this project keeps that
rendering. Both are defensible and neither is a defect — the verifier reads the
timestamp out of the payload it was given, so signatures still verify across the
two. It is reported here because it is a real difference in signed bytes, and
because finding it by surprise later would be worse than reading it now.
"""

import inspect
import sys


def main():
    try:
        from nectar.message import MessageV1 as NV1, MessageV2 as NV2
    except ImportError:
        print("hive-nectar is not importable here; nothing was checked.")
        print("This is a skip, not a pass — run it where nectar is installed.")
        return 2

    from beem.message import MessageV1 as OV1, MessageV2 as OV2

    failures = []
    constants = ("MESSAGE_SPLIT", "SIGNED_MESSAGE_META", "SIGNED_MESSAGE_ENCAPSULATED")

    print("V1 — the constants that decide whether V1 interoperates")
    for field in constants:
        theirs = getattr(NV1, field, None)
        ours = getattr(OV1, field, None)
        if theirs is None or ours is None:
            missing = "nectar" if theirs is None else "this project"
            failures.append(f"V1.{field} is missing on {missing}")
        elif theirs != ours:
            failures.append(f"V1.{field} differs:\n    nectar: {theirs!r}\n    ours  : {ours!r}")
        else:
            print(f"  ok  V1.{field}")

    print("\nV2 — a JSON payload, so the V1 constants do not apply")
    for field in constants:
        if getattr(NV2, field, None) is not None or getattr(OV2, field, None) is not None:
            failures.append(
                f"V2.{field} now exists on one of them. V2 was a JSON payload when this "
                "check was written; if that changed, the comparison below is stale."
            )
    print("  ok  neither defines the V1 constants, as expected")

    their_sign = inspect.getsource(NV2.sign)
    our_sign = inspect.getsource(OV2.sign)
    for token, what in (
        ('separators=(",", ":")', "the JSON separators"),
        ('"from"', "the payload's first key"),
        ('"key"', "the payload's key field"),
        ('"time"', "the payload's time field"),
        ('"text"', "the payload's text field"),
    ):
        if token in their_sign and token in our_sign:
            print(f"  ok  both use {what}")
        else:
            missing = "nectar" if token not in their_sign else "this project"
            failures.append(f"{what} ({token}) is absent from {missing}'s MessageV2.sign")

    # The known divergence. Asserted in both directions so it fails if either side
    # changes -- including if nectar adopts beem's rendering and the note here
    # becomes wrong.
    their_naive = "replace(tzinfo=None)" in their_sign
    our_naive = "replace(tzinfo=None)" in our_sign
    if their_naive or not our_naive:
        failures.append(
            "the documented timestamp divergence no longer holds: nectar naive="
            f"{their_naive}, ours naive={our_naive}. Update this check and "
            "COMPARISON.md together."
        )
    else:
        print(
            "  ok  known divergence intact: nectar stamps an offset-aware timestamp,\n"
            "      this project keeps beem's naive rendering (signatures still verify,\n"
            "      because the verifier reads the timestamp from the payload it is given)"
        )

    if failures:
        print("\nthe message formats do not agree as documented:\n")
        for f in failures:
            print(f"  FAIL  {f}")
        print("\nCorrect the claim in COMPARISON.md before correcting anything else.")
        return 1

    print("\nV1 envelope identical; V2 payload the same shape with one known difference")
    return 0


if __name__ == "__main__":
    sys.exit(main())
