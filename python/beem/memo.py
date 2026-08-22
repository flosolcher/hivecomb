"""Encrypted memos.

Drop-in for `beem.memo.Memo`, backed by `comb`.

**Fixed relative to beem.** Every reference implementation writes the memo as a
Graphene string — a varint length, then the UTF-8 bytes — before encrypting.
beem's ``encode_memo`` omitted the prefix while its ``decode_memo`` tried to
strip one, so it encoded in one format and decoded in another (finding 24).
:meth:`Memo.encrypt` writes the prefix; :meth:`Memo.decrypt` accepts memos
without one, so anything beem produced is still readable.

Note what the format does and does not give you: **confidentiality, not
integrity.** The 4-byte check field is a checksum of the derived key, not of the
ciphertext, and there is no MAC. That is Hive's design, not a choice made here.
"""

from __future__ import annotations

import comb

from .account import Account
from .exceptions import MissingKeyError, WrongMemoKey
from .instance import BlockchainInstance

__all__ = ["Memo"]


class Memo:
    """Encrypt and decrypt account-to-account memos."""

    def __init__(self, from_account=None, to_account=None, **kwargs):
        self._instance = BlockchainInstance(**kwargs)
        self.from_account = from_account
        self.to_account = to_account

    @property
    def blockchain(self):
        return self._instance.blockchain

    def _memo_key(self, account):
        if account is None:
            return None
        if isinstance(account, str) and account.startswith(("STM", "TST", "STX")):
            return account
        name = getattr(account, "name", str(account))
        return Account(name, blockchain_instance=self.blockchain)["memo_key"]

    def encrypt(self, memo, bts_encrypt=False, return_enc_memo_only=False, nonce=None,
                wif=None):
        """Encrypt ``memo`` to the recipient's memo key.

        The signing key comes from ``wif``, or from the keys the `Hive` instance
        was given.
        """
        if not memo:
            return memo
        recipient = self._memo_key(self.to_account)
        if recipient is None:
            raise WrongMemoKey("no recipient memo key")
        sender_wif = wif or _first_key(self.blockchain)
        if sender_wif is None:
            raise MissingKeyError("no memo key available to encrypt with")
        encrypted = comb.encode_memo(str(sender_wif), recipient, str(memo), nonce)
        if return_enc_memo_only:
            return encrypted
        return {"message": encrypted, "from": recipient, "to": recipient}

    def decrypt(self, memo, wif=None):
        """Decrypt a ``#``-prefixed memo with whichever end's key you hold."""
        if not memo:
            return memo
        text = memo["message"] if isinstance(memo, dict) else str(memo)
        if not comb.is_encrypted_memo(text):
            return text
        key = wif or _first_key(self.blockchain)
        if key is None:
            raise MissingKeyError("no memo key available to decrypt with")
        return comb.decode_memo(str(key), text)

    def __repr__(self):
        return f"<Memo {self.from_account} -> {self.to_account}>"


def _first_key(blockchain):
    keys = getattr(blockchain, "wifs", None) or []
    return keys[0] if keys else None
