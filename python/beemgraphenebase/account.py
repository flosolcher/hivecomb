"""Key types.

Drop-in for `beemgraphenebase.account`, backed by `hivecomb`.

**Rendering of secrets matches beem, deliberately.** ``repr(PrivateKey)``
returns the raw private scalar as hex and ``str(PrivateKey)`` returns the WIF,
because real code depends on both and a drop-in that changed them would not be a
drop-in. That is finding 9, reproduced here on purpose and nowhere else in this
project: the Rust API and the native `hivecomb` Python API both redact.

Set ``COMB_COMPAT_REDACT_KEYS=1`` to make both redact, once you have checked
your code does not rely on them.

What *is* fixed underneath: the scalar is range-checked (beem's only check was a
bare ``assert``, which ``python -O`` strips — findings 12 and 13), the WIF
version byte and checksum are verified (finding 11), invalid base58 is rejected
rather than decoded to wrong bytes (finding 10), and key ordering is by the
serialized key rather than by the ripemd160 address (finding 21).
"""

from __future__ import annotations

import hashlib
import re

import hivecomb

from hivecomb_compat import REDACT_KEYS, not_implemented

__all__ = ["PrivateKey", "PublicKey", "PasswordKey", "BrainKey", "Address", "Mnemonic"]

_REDACTED = "<redacted: unset COMB_COMPAT_REDACT_KEYS to match beem>"
_B58 = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _normalize(seed):
    """Collapse whitespace runs to single spaces, as Graphene does."""
    return " ".join(re.compile(r"[\t\n\v\f\r ]+").split(seed)).strip()


def _b58_decode(text):
    n = 0
    for char in text.encode("ascii"):
        index = _B58.find(bytes([char]))
        if index < 0:
            raise ValueError("invalid base58")
        n = n * 58 + index
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return b"\x00" * (len(text) - len(text.lstrip("1"))) + raw


def _b58_encode(data):
    n = int.from_bytes(data, "big")
    out = bytearray()
    while n > 0:
        n, rem = divmod(n, 58)
        out.append(_B58[rem])
    out.reverse()
    return "1" * (len(data) - len(data.lstrip(b"\x00"))) + out.decode("ascii")


def _wif_to_scalar(wif):
    """Decode a WIF to its 32 raw scalar bytes, checking version and checksum."""
    raw = _b58_decode(wif)
    payload, checksum = raw[:-4], raw[-4:]
    if hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4] != checksum:
        raise ValueError("WIF checksum mismatch")
    if payload[0] != 0x80:
        raise ValueError(f"unexpected WIF version byte 0x{payload[0]:02x}")
    return payload[1:]


def _hex_pubkey_to_prefixed(hex_key, prefix):
    """Turn a bare 33-byte hex public key into its prefixed, checksummed form."""
    import hashlib as _h

    raw = bytes.fromhex(hex_key)
    if len(raw) != 33:
        raise ValueError(f"a compressed public key is 33 bytes, got {len(raw)}")
    try:
        ripemd = _h.new("ripemd160")
    except ValueError as exc:  # OpenSSL 3 without the legacy provider
        raise ValueError(
            "this Python's hashlib has no ripemd160, so a bare hex public key "
            "cannot be re-checksummed; pass the prefixed form instead"
        ) from exc
    ripemd.update(raw)
    return prefix + _b58_encode(raw + ripemd.digest()[:4])


class PublicKey:
    """A Hive public key."""

    def __init__(self, pk, prefix="STM"):
        self.prefix = prefix
        if isinstance(pk, PublicKey):
            self._key = pk._key
        elif isinstance(pk, hivecomb.PublicKey):
            self._key = pk
        else:
            text = str(pk).strip()
            if text.startswith(("STM", "TST", "STX")):
                self._key = hivecomb.PublicKey(text)
            else:
                self._key = hivecomb.PublicKey(_hex_pubkey_to_prefixed(text, prefix))

    def __repr__(self):
        """The compressed key as hex, matching beem."""
        return self._key.to_hex()

    def __str__(self):
        return self._key.to_string_with_prefix(self.prefix)

    def __format__(self, spec):
        """``format(key, "STM")`` renders with that prefix, as beem does."""
        return self._key.to_string_with_prefix(spec or self.prefix)

    def __bytes__(self):
        return bytes.fromhex(self._key.to_hex())

    def __eq__(self, other):
        if isinstance(other, PublicKey):
            return self._key == other._key
        return NotImplemented

    def __hash__(self):
        return hash(self._key.to_hex())

    def __lt__(self, other):
        """Order by the serialized key.

        beem ordered by the ripemd160 *address*, which gives a different order
        and therefore different signed bytes for any authority holding more than
        one key (finding 21).
        """
        return self._key.to_hex() < other._key.to_hex()

    @property
    def pubkey(self):
        return self

    def get_public_key(self):
        return self

    def compressed(self):
        return self._key.to_hex()

    def unCompressed(self):
        raise not_implemented(
            "PublicKey.unCompressed",
            "Hive serializes only compressed keys.",
        )

    uncompressed = unCompressed

    @property
    def address(self):
        raise not_implemented(
            "PublicKey.address",
            "Graphene addresses are not used anywhere in Hive's protocol.",
        )


class PrivateKey:
    """A Hive private key."""

    def __init__(self, wif=None, prefix="STM"):
        self.prefix = prefix
        if wif is None:
            self._key = hivecomb.PrivateKey.generate()
        elif isinstance(wif, PrivateKey):
            self._key = wif._key
        elif isinstance(wif, hivecomb.PrivateKey):
            self._key = wif
        else:
            self._key = hivecomb.PrivateKey(str(wif))

    def __repr__(self):
        """The raw scalar as hex — matching beem. See the module docstring."""
        if REDACT_KEYS:
            return _REDACTED
        return bytes(self).hex()

    def __str__(self):
        """The WIF — matching beem. See the module docstring."""
        if REDACT_KEYS:
            return _REDACTED
        return self._key.to_wif()

    def __format__(self, spec):
        if spec.upper() == "WIF":
            return self._key.to_wif()
        raise not_implemented(f"PrivateKey format {spec!r}", "Only 'WIF' is supported.")

    def __bytes__(self):
        return _wif_to_scalar(self._key.to_wif())

    def __eq__(self, other):
        if isinstance(other, PrivateKey):
            return self._key == other._key
        return NotImplemented

    def __hash__(self):
        return hash(self._key.to_wif())

    @property
    def pubkey(self):
        return PublicKey(self._key.public_key(), prefix=self.prefix)

    @property
    def compressed(self):
        return self.pubkey

    def get_public_key(self):
        return self.pubkey

    def get_secret(self):
        return hashlib.sha256(bytes(self)).digest()

    @property
    def bitcoin(self):
        raise not_implemented(
            "PrivateKey.bitcoin",
            "Bitcoin address derivation is internal to BIP-38, which hivecomb "
            "implements directly (PrivateKey.to_bip38).",
        )

    def derive_private_key(self, sequence):
        """Graphene's sequence derivation: ``sha256(sha512(f'{wif} {sequence}'))``."""
        encoded = f"{self._key.to_wif()} {int(sequence)}".encode("ascii")
        scalar = hashlib.sha256(hashlib.sha512(encoded).digest()).digest()
        return PrivateKey(hivecomb.PrivateKey(scalar.hex()), prefix=self.prefix)

    def child(self, offset256):
        raise not_implemented(
            "PrivateKey.child",
            "Use hivecomb.PrivateKey.from_mnemonic() for BIP-32 derivation.",
        )


class PasswordKey:
    """Derives a role key from an account name and master password.

    One unsalted SHA-256, no work factor (finding 20). That is Hive's scheme,
    not beem's, and cannot change without breaking compatibility. Prefer an
    explicit key or a BIP-39 mnemonic.
    """

    def __init__(self, account, password, role="active", prefix="STM"):
        self.account = account
        self.password = password
        self.role = role
        self.prefix = prefix

    def get_private(self):
        return PrivateKey(
            hivecomb.PrivateKey.from_password(self.account or "", self.role, self.password),
            prefix=self.prefix,
        )

    def get_public(self):
        return self.get_private().pubkey

    get_private_key = get_private
    get_public_key = get_public


class BrainKey:
    """A Graphene brain key."""

    def __init__(self, brainkey=None, sequence=0, prefix="STM"):
        self.prefix = prefix
        self.sequence = sequence
        if brainkey is None:
            raise not_implemented(
                "BrainKey() with no phrase",
                "Generating a brain key is not supported; beem's generator was "
                "biased (finding 14). Use hivecomb.generate_mnemonic() instead.",
            )
        self.brainkey = _normalize(brainkey)

    def __next__(self):
        self.sequence += 1
        return self

    def next_sequence(self):
        return self.__next__()

    def normalize(self, brainkey):
        return _normalize(brainkey)

    def get_brainkey(self):
        return _normalize(self.brainkey)

    def get_private(self):
        return PrivateKey(
            hivecomb.PrivateKey.from_brain_key(self.brainkey, self.sequence),
            prefix=self.prefix,
        )

    def get_public(self):
        return self.get_private().pubkey

    get_private_key = get_private
    get_public_key = get_public

    def suggest(self, word_count=16):
        raise not_implemented(
            "BrainKey.suggest",
            "beem's generator was biased roughly 2:1 across the dictionary and "
            "could index past the end (finding 14). Use "
            "hivecomb.generate_mnemonic(), which is uniform and checksummed.",
        )


class Address:
    """Not provided: Graphene addresses are unused in Hive's protocol."""

    def __init__(self, *args, **kwargs):
        raise not_implemented("Address", "Hive identifies keys by their prefixed form.")


class Mnemonic:
    """BIP-39 mnemonics, routed through `hivecomb`."""

    def generate(self, strength=128):
        return hivecomb.generate_mnemonic(strength)

    def check(self, mnemonic):
        return hivecomb.validate_mnemonic(mnemonic)

    def to_mnemonic(self, data):
        raise not_implemented("Mnemonic.to_mnemonic", "Use hivecomb.generate_mnemonic().")

    @classmethod
    def to_seed(cls, mnemonic, passphrase=""):
        raise not_implemented(
            "Mnemonic.to_seed",
            "Use hivecomb.PrivateKey.from_mnemonic(mnemonic, role, ...), which "
            "derives the Hive role key directly via BIP-32/BIP-48.",
        )
