"""The key store.

Drop-in for `beem.wallet.Wallet`, backed by `hivecomb`'s encrypted key store.

**Fixed relative to beem.** beem encrypted stored keys under
``AESCipher(sha256(passphrase))`` — one unsalted SHA-256, no work factor — with
AES-CBC and no MAC (finding 25). This one uses scrypt and AES-256-GCM, so
guesses cost real work, two users with the same passphrase get different keys,
and a tampered wallet file fails authentication rather than decrypting.

**The file format is not beem's**, deliberately: reading beem's would mean
shipping the weak construction. Migrate with ``beempy listkeys`` under old beem,
then ``beempy addkey`` here.

The default location is ``~/.config/hivecomb/wallet.json``; override with
``COMB_WALLET`` or the ``path`` argument.
"""

from __future__ import annotations

import os
from pathlib import Path

import hivecomb

from .exceptions import (
    KeyNotFound,
    MissingKeyError,
    NoWalletException,
    WalletExists,
    WalletLocked,
    WrongMasterPasswordException,
)
from .instance import BlockchainInstance

__all__ = ["Wallet", "default_wallet_path"]


def default_wallet_path():
    """Where the wallet lives unless told otherwise."""
    override = os.environ.get("COMB_WALLET")
    if override:
        return Path(override)
    base = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    return base / "hivecomb" / "wallet.json"


class Wallet:
    """An encrypted store of private keys."""

    def __init__(self, path=None, keys=None, **kwargs):
        self._instance = BlockchainInstance(**kwargs)
        self.path = Path(path) if path else default_wallet_path()
        self._wallet = None
        #: Keys supplied directly, used before the store is consulted.
        self._direct = {}
        if keys:
            self.setKeys(keys)

    # -- lifecycle ---------------------------------------------------------

    @property
    def created(self):
        return self.path.exists()

    def create(self, pwd):
        """Create the wallet. Refuses to overwrite an existing one."""
        if self.path.exists():
            raise WalletExists(f"{self.path} already exists")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._wallet = hivecomb.Wallet.create(str(self.path), pwd)
        return self

    def unlock(self, pwd):
        """Unlock with the master passphrase."""
        if not self.path.exists():
            raise NoWalletException(f"no wallet at {self.path}")
        wallet = hivecomb.Wallet.open(str(self.path))
        try:
            wallet.unlock(pwd)
        except ValueError as exc:
            raise WrongMasterPasswordException(str(exc)) from exc
        self._wallet = wallet
        return self

    def lock(self):
        if self._wallet is not None:
            self._wallet.lock()
        return self

    def locked(self):
        return self._wallet is None or self._wallet.is_locked()

    def unlocked(self):
        return not self.locked()

    def changePassphrase(self, new_pwd):
        self._require_unlocked()
        self._wallet.change_passphrase(new_pwd)
        return self

    def _require_unlocked(self):
        if self._wallet is None:
            raise NoWalletException("no wallet is open; call create() or unlock()")
        if self._wallet.is_locked():
            raise WalletLocked("the wallet is locked")

    # -- direct keys -------------------------------------------------------

    def setKeys(self, loadkeys):
        """Use these keys directly, without a store.

        beem's equivalent of running with ``keys=[...]`` and no wallet file.
        """
        if isinstance(loadkeys, str):
            loadkeys = [loadkeys]
        if isinstance(loadkeys, dict):
            loadkeys = list(loadkeys.values())
        self._direct = {}
        for wif in loadkeys:
            key = hivecomb.PrivateKey(str(wif))
            self._direct[str(key.public_key())] = str(wif)
        return self

    def is_encrypted(self):
        return self._wallet is not None

    # -- keys --------------------------------------------------------------

    def addPrivateKey(self, wif, account=None, role=None):
        """Store a key, optionally tagged with the account and role."""
        self._require_unlocked()
        return self._wallet.add_key(str(wif), account, role)

    def removePrivateKeyFromPublicKey(self, pub):
        self._require_unlocked()
        if not self._wallet.remove_key(str(pub)):
            raise KeyNotFound(f"{pub} is not in the wallet")
        return True

    removeAccount = removePrivateKeyFromPublicKey

    def getPublicKeys(self, current=False):
        if self._wallet is not None:
            return self._wallet.public_keys()
        return list(self._direct)

    def getPrivateKeyForPublicKey(self, pub):
        """The WIF for a public key."""
        pub = str(pub)
        if pub in self._direct:
            return self._direct[pub]
        self._require_unlocked()
        try:
            return self._wallet.get_key(pub)
        except ValueError as exc:
            raise KeyNotFound(str(exc)) from exc

    def getKeyForAccount(self, name, key_type):
        """The WIF for an account's role.

        Looks in the store's own index first, then falls back to matching the
        account's on-chain key against what is held — which is how beem found
        keys, and needs a node.
        """
        if self._wallet is not None and not self._wallet.is_locked():
            try:
                return self._wallet.get_key_for_role(name, key_type)
            except ValueError:
                pass
        return self._match_on_chain(name, key_type)

    def _match_on_chain(self, name, key_type):
        from .account import Account

        account = Account(name, blockchain_instance=self._instance.blockchain)
        if key_type == "memo":
            wanted = {account["memo_key"]}
        else:
            authority = account.get(key_type)
            if not authority:
                raise MissingKeyError(f"{name} has no {key_type} authority")
            wanted = {entry[0] for entry in authority.get("key_auths", [])}
        for public in self.getPublicKeys():
            if public in wanted:
                return self.getPrivateKeyForPublicKey(public)
        raise MissingKeyError(f"no {key_type} key for {name} is available")

    def getOwnerKeyForAccount(self, name):
        return self.getKeyForAccount(name, "owner")

    def getActiveKeyForAccount(self, name):
        return self.getKeyForAccount(name, "active")

    def getPostingKeyForAccount(self, name):
        return self.getKeyForAccount(name, "posting")

    def getMemoKeyForAccount(self, name):
        return self.getKeyForAccount(name, "memo")

    def getAccounts(self):
        """Accounts the store knows about, readable while locked."""
        if self._wallet is None:
            return []
        return sorted(self._wallet.index())

    def getAccountsFromPublicKey(self, pub):
        result = self._instance.blockchain.rpc.call(
            "account_by_key_api.get_key_references", {"keys": [str(pub)]}
        )
        accounts = result.get("accounts") or [[]]
        return accounts[0]

    def wipe(self, sure=False):
        if not sure:
            raise ValueError("wipe(sure=True) deletes every stored key")
        if self.path.exists():
            self.path.unlink()
        self._wallet = None
        return True

    def __len__(self):
        return len(self.getPublicKeys())

    def __repr__(self):
        state = "unlocked" if self.unlocked() else "locked"
        return f"<Wallet {self.path} {state} keys={len(self)}>"
