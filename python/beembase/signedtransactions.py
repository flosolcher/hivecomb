"""Signed transactions.

Drop-in for `beembase.signedtransactions.Signed_Transaction`, backed by `hivecomb`.

Two things differ, both deliberate:

* **The chain id is not looked up.** ``sign(chain=...)`` takes a chain *name*
  and resolves it to a compiled-in constant. beem accepted a dict and fell back
  to the pre-HF24 all-zero id when a node call failed (finding 5).
* **``verify`` verifies.** beem looped over all four recovery parameters and
  appended every candidate that did not raise, so its result could hold four
  unrelated keys for one signature (findings 6 and 7).
"""

from __future__ import annotations

import hivecomb

from hivecomb_compat import not_implemented

__all__ = ["Signed_Transaction"]


class Signed_Transaction:
    """Build, sign and verify a transaction."""

    def __init__(self, ref_block_num=None, ref_block_prefix=None, expiration=None,
                 operations=None, signatures=None, **kwargs):
        if ref_block_num is None or ref_block_prefix is None:
            raise ValueError("a transaction needs ref_block_num and ref_block_prefix")
        if not operations:
            raise ValueError("a transaction needs at least one operation")
        self.ref_block_num = int(ref_block_num)
        self.ref_block_prefix = int(ref_block_prefix)
        self.expiration = expiration
        self.operations = [_as_pair(op) for op in operations]
        self.signatures = list(signatures or [])
        self._chain = kwargs.pop("chain", "HIVE")

    # hivecomb takes a BlockRef; reconstruct one from the two reference fields.
    def _block_ref(self):
        return hivecomb.BlockRef.from_parts(self.ref_block_num, self.ref_block_prefix)

    def derive_digest(self, chain="HIVE"):
        """The digest that gets signed: ``sha256(chain_id || serialized_tx)``."""
        return hivecomb.transaction_digest(
            self.operations, self._block_ref(), self.expiration, chain=_chain_name(chain)
        )

    #: beem's spelling.
    deriveDigest = derive_digest

    @property
    def id(self):
        """The transaction id."""
        return hivecomb.transaction_id(
            self.operations, self._block_ref(), self.expiration, chain=self._chain
        )

    def sign(self, wifkeys, chain="HIVE"):
        """Sign with the given WIF keys."""
        if not wifkeys:
            raise ValueError("no signing keys were provided")
        result = hivecomb.sign_transaction(
            self.operations,
            self._block_ref(),
            [str(k) for k in wifkeys],
            chain=_chain_name(chain),
        )
        self.signatures = result["signatures"]
        self.expiration = result["expiration"]
        return self

    def verify(self, pubkeys=None, chain="HIVE", recover_parameter=False):
        """Return the public keys that signed this transaction.

        Every signature must verify; one that does not raises. beem returned up
        to four unrelated keys per signature.
        """
        digest = self.derive_digest(chain)
        found = []
        for signature in self.signatures:
            found.append(hivecomb.recover_digest(digest, signature))
        if pubkeys:
            have = {str(k) for k in found}
            for key in pubkeys:
                if str(key) not in have:
                    raise ValueError(f"signature for {key} missing")
        return found

    def json(self):
        return {
            "ref_block_num": self.ref_block_num,
            "ref_block_prefix": self.ref_block_prefix,
            "expiration": self.expiration,
            "operations": self.operations,
            "extensions": [],
            "signatures": self.signatures,
        }

    toJson = json

    def __bytes__(self):
        raise not_implemented(
            "bytes(Signed_Transaction)",
            "Use derive_digest() for the signed bytes' hash, or "
            "hivecomb.sign_transaction for the broadcast form.",
        )


def _as_pair(op):
    """Normalise an operation into the ``(name, fields)`` pair hivecomb takes."""
    if hasattr(op, "json"):
        op = op.json()
    if isinstance(op, (list, tuple)) and len(op) == 2:
        return (op[0], dict(op[1]))
    if isinstance(op, dict) and "type" in op:
        return (op["type"].replace("_operation", ""), dict(op["value"]))
    raise ValueError(f"cannot read {op!r} as an operation")


def _chain_name(chain):
    """Accept a chain name or beem's chain dict."""
    if isinstance(chain, dict):
        chain_id = chain.get("chain_id", "")
        if set(chain_id) == {"0"}:
            raise ValueError(
                "refusing to sign against the all-zero chain id: it is the "
                "pre-HF24 value and produces a signature Hive rejects"
            )
        return "HIVE"
    return str(chain)
