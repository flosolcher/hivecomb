"""Signed messages, in the two formats beem produced.

Drop-in for `beem.message`. The V1 envelope —
``-----BEGIN HIVE SIGNED MESSAGE-----`` — is a de-facto Hive standard used to prove
control of an account without broadcasting anything, so the bytes here have to match
what other tools produce character for character. They are reproduced from beem's
templates rather than rewritten.

Both formats sign with the account's **memo key**, not a posting or active key. That is
beem's choice and it is a reasonable one: the memo key is the only one that is not an
authority, so proving control of it proves identity without proving spending power.

What is different underneath:

* the signature comes from `hivecomb`, so it is a canonical compact signature produced
  with an RFC 6979 nonce rather than beem's wall-clock-seeded one (finding 4);
* `verify()` checks the recovered key against the account's memo key and **returns the
  result**. beem's `verify_message` computed a tautology and discarded it (finding 6);
* the account lookup goes through this layer's `Account`, which reads from the node
  rather than reconstructing state locally.

`beem.message` was neither implemented nor declared missing until this file existed: a
drop-in user calling it got a bare ``ModuleNotFoundError``.
"""

from __future__ import annotations

import json
import re
from binascii import hexlify, unhexlify
from datetime import datetime, timezone

import hivecomb

from .account import Account
from .exceptions import (
    AccountDoesNotExistsException,
    InvalidMemoKeyException,
    InvalidMessageSignature,
    WrongMemoKey,
)
from .instance import shared_blockchain_instance

__all__ = ["Message", "MessageV1", "MessageV2"]


class MessageV1:
    """The encapsulated envelope format.

    The signed payload is *not* the envelope: it is the message followed by four
    ``key=value`` lines, exactly as laid out in :attr:`SIGNED_MESSAGE_META`. Getting
    that wrong produces a signature no other client will accept, which is why the
    templates are copied rather than reconstructed.
    """

    MESSAGE_SPLIT = (
        "-----BEGIN HIVE SIGNED MESSAGE-----",
        "-----BEGIN META-----",
        "-----BEGIN SIGNATURE-----",
        "-----END HIVE SIGNED MESSAGE-----",
    )

    SIGNED_MESSAGE_META = """{message}
account={meta[account]}
memokey={meta[memokey]}
block={meta[block]}
timestamp={meta[timestamp]}"""

    SIGNED_MESSAGE_ENCAPSULATED = """
{MESSAGE_SPLIT[0]}
{message}
{MESSAGE_SPLIT[1]}
account={meta[account]}
memokey={meta[memokey]}
block={meta[block]}
timestamp={meta[timestamp]}
{MESSAGE_SPLIT[2]}
{signature}
{MESSAGE_SPLIT[3]}"""

    def __init__(self, message, blockchain_instance=None, **kwargs):
        blockchain_instance = blockchain_instance or (
            kwargs.get("steem_instance") or kwargs.get("hive_instance")
        )
        self.blockchain = blockchain_instance or shared_blockchain_instance()
        # Normalise line endings before anything is signed: CRLF and LF must not
        # produce different signatures for what a human typed as the same message.
        self.message = message.replace("\r\n", "\n") if isinstance(message, str) else message
        self.signed_by_account = None
        self.signed_by_name = None
        self.meta = None
        self.plain_message = None

    def _memo_wif(self, account):
        """The private memo key for `account`, from the wallet or from the instance."""
        memo_key = account["memo_key"]
        wallet = getattr(self.blockchain, "wallet", None)
        if wallet is not None:
            try:
                return wallet.getPrivateKeyForPublicKey(memo_key)
            except Exception:  # noqa: BLE001 - fall through to the instance's keys
                pass
        for wif in getattr(self.blockchain, "wifs", []) or []:
            if str(hivecomb.PrivateKey(wif).public_key()) == memo_key:
                return wif
        raise ValueError(
            f"no private memo key for @{account['name']} is available; "
            f"add the key matching {memo_key} to the wallet or to Hive(keys=[...])"
        )

    def sign(self, account=None, **kwargs):
        """Sign, returning the encapsulated envelope as a string."""
        if not account:
            account = self.blockchain.config.get("default_account")
        if not account:
            raise ValueError("You need to provide an account")

        account = Account(account, blockchain_instance=self.blockchain)
        info = self.blockchain.info()
        meta = {
            "timestamp": info["time"],
            "block": info["head_block_number"],
            "memokey": account["memo_key"],
            "account": account["name"],
        }
        wif = self._memo_wif(account)

        # Stripped so that trailing whitespace cannot change the signature.
        message = self.message.strip()
        enc_message = self.SIGNED_MESSAGE_META.format(message=message, meta=meta)
        signature = hivecomb.sign_message(enc_message, wif)
        if isinstance(signature, (bytes, bytearray)):
            signature = hexlify(signature).decode("ascii")

        self.signed_by_account = account
        self.signed_by_name = account["name"]
        self.meta = meta
        self.plain_message = message

        return self.SIGNED_MESSAGE_ENCAPSULATED.format(
            MESSAGE_SPLIT=self.MESSAGE_SPLIT,
            message=message,
            meta=meta,
            signature=signature,
        )

    def verify(self, **kwargs):
        """Verify an envelope. Returns True, or raises saying why not."""
        parts = re.split("|".join(self.MESSAGE_SPLIT), self.message)
        parts = [x for x in parts if x.strip()]
        if len(parts) <= 2:
            raise AssertionError("Incorrect number of message parts")

        message = parts[0].strip()
        signature = parts[2].strip()
        meta = dict(re.findall(r"(\S+)=(.*)", parts[1]))

        for field in ("account", "memokey", "block", "timestamp"):
            if field not in meta:
                raise AssertionError(f"No '{field}' could be found in meta data")

        account_name = meta["account"].strip()
        memo_key = meta["memokey"].strip()

        try:
            hivecomb.PublicKey(memo_key)
        except Exception as exc:  # noqa: BLE001 - re-raised as beem's type
            raise InvalidMemoKeyException(
                "The memo key in the message is invalid"
            ) from exc

        try:
            account = Account(account_name, blockchain_instance=self.blockchain)
        except AccountDoesNotExistsException:
            raise AccountDoesNotExistsException(
                f"Could not find account {account_name}. "
                "Are you connected to the right chain?"
            ) from None

        # The envelope names a memo key; the chain is the authority on whether that
        # is really the account's. Without this check a signature proves only that
        # someone holds the key they themselves named.
        if account["memo_key"] != memo_key:
            raise WrongMemoKey(
                f"Memo Key of account {account['name']} on the Blockchain "
                f"differs from memo key in the message: "
                f"{account['memo_key']} != {memo_key}"
            )

        enc_message = self.SIGNED_MESSAGE_META.format(message=message, meta=meta)
        recovered = hivecomb.recover_message(enc_message, signature)
        if str(recovered) != memo_key:
            raise InvalidMessageSignature(
                "The signature doesn't match the memo key"
            )

        self.signed_by_account = account
        self.signed_by_name = account["name"]
        self.meta = meta
        self.plain_message = message
        return True


class MessageV2:
    """The JSON payload format: a flat list, signed as compact JSON."""

    def __init__(self, message, blockchain_instance=None, **kwargs):
        blockchain_instance = blockchain_instance or (
            kwargs.get("steem_instance") or kwargs.get("hive_instance")
        )
        self.blockchain = blockchain_instance or shared_blockchain_instance()
        self.message = message
        self.signed_by_account = None
        self.signed_by_name = None
        self.meta = None
        self.plain_message = None

    _memo_wif = MessageV1._memo_wif

    def sign(self, account=None, **kwargs):
        """Sign, returning ``{"signed", "payload", "signature"}``."""
        if not account:
            account = self.blockchain.config.get("default_account")
        if not account:
            raise ValueError("You need to provide an account")

        account = Account(account, blockchain_instance=self.blockchain)
        wif = self._memo_wif(account)

        # beem used `datetime.utcnow()`, which is naive and deprecated. This is the
        # same wall-clock instant, spelled so it cannot be read as local time.
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        payload = [
            "from", account["name"],
            "key", account["memo_key"],
            "time", str(now),
            "text", self.message,
        ]
        enc_message = json.dumps(payload, separators=(",", ":"))
        signature = hivecomb.sign_message(enc_message, wif)
        if isinstance(signature, (bytes, bytearray)):
            signature = hexlify(signature).decode("ascii")

        self.signed_by_account = account
        self.signed_by_name = account["name"]
        self.meta = dict(zip(payload[::2], payload[1::2]))
        self.plain_message = self.message

        return {"signed": enc_message, "payload": payload, "signature": signature}

    def verify(self, **kwargs):
        message = self.message
        if not isinstance(message, dict):
            message = json.loads(message)

        payload = message.get("payload")
        signature = message.get("signature")
        if not payload or not signature:
            raise AssertionError("Not a V2 signed message")

        fields = dict(zip(payload[::2], payload[1::2]))
        account_name = fields.get("from")
        memo_key = fields.get("key")
        if not account_name or not memo_key:
            raise AssertionError("V2 payload is missing 'from' or 'key'")

        try:
            hivecomb.PublicKey(memo_key)
        except Exception as exc:  # noqa: BLE001
            raise InvalidMemoKeyException(
                "The memo key in the message is invalid"
            ) from exc

        account = Account(account_name, blockchain_instance=self.blockchain)
        if account["memo_key"] != memo_key:
            raise WrongMemoKey(
                f"Memo Key of account {account['name']} on the Blockchain "
                f"differs from memo key in the message: "
                f"{account['memo_key']} != {memo_key}"
            )

        enc_message = message.get("signed") or json.dumps(
            payload, separators=(",", ":")
        )
        recovered = hivecomb.recover_message(enc_message, signature)
        if str(recovered) != memo_key:
            raise InvalidMessageSignature("The signature doesn't match the memo key")

        self.signed_by_account = account
        self.signed_by_name = account["name"]
        self.meta = fields
        self.plain_message = fields.get("text")
        return True


class Message(MessageV1, MessageV2):
    """Tries each format in turn, as beem's did.

    beem swallowed every exception from a format that did not apply and re-raised only
    its own four. That is kept, because code depending on the drop-in may rely on
    catching those types — but a message that no format accepts raises rather than
    returning a falsy value.
    """

    supported_formats = (MessageV1, MessageV2)
    valid_exceptions = (
        AccountDoesNotExistsException,
        InvalidMessageSignature,
        WrongMemoKey,
        InvalidMemoKeyException,
    )

    def __init__(self, message, blockchain_instance=None, **kwargs):
        MessageV1.__init__(self, message, blockchain_instance, **kwargs)

    def sign(self, *args, **kwargs):
        for fmt in self.supported_formats:
            try:
                return fmt.sign(self, *args, **kwargs)
            except self.valid_exceptions:
                raise
            except Exception:  # noqa: BLE001 - try the next format
                continue
        raise ValueError("No Encoder accepted the message")

    def verify(self, **kwargs):
        for fmt in self.supported_formats:
            try:
                return fmt.verify(self, **kwargs)
            except self.valid_exceptions:
                raise
            except Exception:  # noqa: BLE001 - try the next format
                continue
        raise ValueError("No Decoder accepted the message")
