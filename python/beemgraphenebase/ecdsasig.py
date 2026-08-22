"""Signing and verification.

Drop-in for `beemgraphenebase.ecdsasig`.

Under the hood this is libsecp256k1 via `comb`, with one constant-time code
path. beem selected between four backends at import time inside a bare
``except:`` and, with none installed, fell through to pure-Python variable-time
ECDSA — the Minerva primitive (findings 3 and 4). There is no backend selection
here, so ``SECP256K1_MODULE`` is reported as ``"comb"`` for any code that
inspects it.

Nonces come from RFC 6979 with an incrementing counter, so signatures are
deterministic. beem's pure-Python path seeded them with
``struct.pack("d", time.time())``.
"""

from __future__ import annotations

import hashlib

import comb

from .account import PrivateKey, PublicKey

#: Reported for code that inspects which backend is in use. Always this.
SECP256K1_MODULE = "comb"
SECP256K1_AVAILABLE = True
CRYPTOGRAPHY_AVAILABLE = False
GMPY2_MODULE = False

__all__ = [
    "SECP256K1_MODULE",
    "sign_message",
    "verify_message",
    "compressedPubkey",
    "recover_public_key",
    "recoverPubkeyParameter",
]


def _as_bytes(value):
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    return str(value).encode("utf-8")


def sign_message(message, wif, hashfn=hashlib.sha256):
    """Sign ``message`` with ``wif``, returning the 65-byte compact signature.

    Returns :class:`bytes`, as beem does.

    ``hashfn`` must be SHA-256: Hive's signature scheme is defined over it, and
    accepting another would produce a signature the chain cannot verify. beem
    took the argument and honoured it, which is a way to make an unusable
    signature quietly.
    """
    if hashfn is not hashlib.sha256:
        raise ValueError(
            "Hive signatures are defined over SHA-256; another hash produces a "
            "signature the chain will reject"
        )
    wif = str(wif)
    return bytes.fromhex(comb.sign_message(_as_bytes(message), wif))


def verify_message(message, signature, hashfn=hashlib.sha256, recover_parameter=None):
    """Recover the public key that signed ``message``.

    Returns the compressed public key as :class:`bytes`.

    **This name promises more than the operation can deliver, in beem and here
    alike.** Recovery answers "which key would have produced this signature?", so
    a *tampered* signature does not fail — it recovers a **different** key. The
    only way to decide whether a signature is the one you expected is to compare
    the result against the key you expected::

        assert verify_message(msg, sig) == bytes(expected_pubkey)

    beem's version additionally called ``ecdsa_verify`` and discarded the result
    (finding 6); reading that result would not have helped, because the key being
    checked is the one just recovered from the same signature. What is fixed here
    is narrower and real: a **malformed** signature raises rather than being
    carried forward, and only one candidate is returned rather than beem's four
    (finding 7).

    ``recover_parameter`` is accepted and ignored: the recovery id is carried in
    the signature's own header byte, which is where it belongs.
    """
    if hashfn is not hashlib.sha256:
        raise ValueError("Hive signatures are defined over SHA-256")
    signature = _as_bytes(signature)
    if len(signature) != 65:
        raise ValueError(f"signature must be 65 bytes, got {len(signature)}")
    key = comb.recover_message(_as_bytes(message), signature.hex())
    return bytes.fromhex(key.to_hex())


def compressedPubkey(pk):
    """The compressed encoding of a public key."""
    if isinstance(pk, PublicKey):
        return bytes.fromhex(pk._key.to_hex())
    return _as_bytes(pk)


def recover_public_key(digest, signature, i, message=None):
    """Not provided.

    beem exposed this as part of its multi-backend recovery machinery. Recovery
    is not a public operation here because recovery alone proves nothing — see
    :func:`verify_message`.
    """
    from comb_compat import not_implemented

    raise not_implemented(
        "recover_public_key",
        "Use verify_message, which recovers *and* verifies.",
    )


def recoverPubkeyParameter(message, digest, signature, pubkey):
    """Not provided; the recovery id is in the signature header byte."""
    from comb_compat import not_implemented

    raise not_implemented(
        "recoverPubkeyParameter",
        "The recovery id is byte 0 of the signature.",
    )
