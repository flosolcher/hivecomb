"""The `Hive` class.

Drop-in for `beem.hive.Hive` / `beem.Hive`, backed by `comb`.

# The one behavioural change that matters

**Signing never touches the network.** beem called `get_config` over JSON-RPC on
the way to every signature, partly to look up a chain id that is a compile-time
constant (finding 5). Here the chain id is compiled in and the block reference is
cached with an explicit staleness bound, so producing a signature is pure CPU.

The node is still contacted to *refresh* the block reference and to *broadcast*.
Those are real network operations. The difference is that a slow node can no
longer make signing slow, and a node error can no longer produce a silently
invalid signature.

Set ``tapos_max_age`` to control how long a cached block reference is reused;
past it, the next signature refreshes rather than serving a stale reference.

# Operations beem could not build

`recurrent_transfer` and `collateralized_convert` (both HF25) are absent from
beem's operation table, so `beem` raises `ValueError("Unknown operation")` for
them. They are available here, along with the HF28 `pair_id` extension. See
``MIGRATION.md`` for the full list of additions.
"""

from __future__ import annotations

import json
import time

import comb

from comb_compat import DEFAULT_NODES, NodeClient, not_implemented

__all__ = ["Hive", "Steem"]


class Hive:
    """A Hive chain handle.

    :param node: node URL or list of URLs
    :param keys: WIF keys to sign with, or a mapping of role -> WIF
    :param nobroadcast: build and sign but do not broadcast
    :param expiration: seconds until a transaction expires
    :param tapos_max_age: seconds a cached block reference stays usable
    """

    def __init__(
        self,
        node=None,
        keys=None,
        nobroadcast=False,
        expiration=60,
        tapos_max_age=180,
        num_retries=3,
        timeout=10,
        chain="HIVE",
        **kwargs,
    ):
        self.rpc = NodeClient(
            node or DEFAULT_NODES, timeout=timeout, num_retries=num_retries
        )
        self.nobroadcast = nobroadcast
        self.expiration = expiration
        self.chain = chain
        self._tapos = comb.TaposCache(max_age_seconds=tapos_max_age)
        self.wifs = self._collect_keys(keys)
        self._wallet = kwargs.pop("wallet", None)

        # beem accepted a long tail of constructor arguments. Anything unknown is
        # reported rather than ignored, because silently dropping a setting the
        # caller asked for is how a transaction ends up doing something else.
        unsupported = {
            k: v for k, v in kwargs.items() if k not in _IGNORED_KWARGS
        }
        if unsupported:
            raise not_implemented(
                f"Hive(**{sorted(unsupported)})",
                "These beem options have no equivalent here.",
            )

    # -- key handling -----------------------------------------------------

    @staticmethod
    def _collect_keys(keys):
        if keys is None:
            return []
        if isinstance(keys, str):
            return [keys]
        if isinstance(keys, dict):
            return [str(v) for v in keys.values() if v]
        return [str(k) for k in keys if k]

    @property
    def wallet(self):
        """The key store, created on first use.

        Returns ``None`` when the instance was given keys directly and no wallet
        exists, so callers can tell the two apart.
        """
        if self._wallet is None:
            from .wallet import Wallet, default_wallet_path

            if default_wallet_path().exists():
                self._wallet = Wallet(blockchain_instance=self)
        return self._wallet

    @wallet.setter
    def wallet(self, value):
        self._wallet = value

    def unlock(self, passphrase):
        """Unlock the key store and use its keys for signing."""
        from .wallet import Wallet

        wallet = self._wallet or Wallet(blockchain_instance=self)
        wallet.unlock(passphrase)
        self._wallet = wallet
        return wallet

    def is_hive(self):
        return True

    def is_steem(self):
        return False

    # -- chain state ------------------------------------------------------

    def get_dynamic_global_properties(self, use_stored_data=True):
        return self.rpc.call("database_api.get_dynamic_global_properties", {})

    def get_config(self, use_stored_data=True):
        return self.rpc.call("database_api.get_config", {})

    def get_chain_id(self):
        """The chain id this build signs against.

        A **local constant**, not a node lookup. Use :meth:`verify_chain_id` to
        check a node agrees.
        """
        return comb.chain_id(self.chain)

    def verify_chain_id(self):
        """Check the node's reported chain id against the compiled-in constant.

        beem asked the network for this on every signature and fell back to the
        pre-HF24 all-zero id when the call failed, producing a signature the
        chain rejects with no sign that signing was the problem (finding 5).
        """
        reported = self.get_config().get("HIVE_CHAIN_ID")
        expected = self.get_chain_id()
        if reported is None:
            raise ValueError("node config carries no HIVE_CHAIN_ID")
        if reported.lower() != expected.lower():
            raise ValueError(
                f"node reports chain id {reported}, but this build signs for {expected}"
            )
        return True

    def refresh_block_ref(self):
        """Fetch a fresh TaPoS reference and cache it."""
        props = self.get_dynamic_global_properties()
        self._tapos.store_block_id(props["head_block_id"])
        return self._tapos.block_ref()

    def _block_ref(self):
        """The cached reference, refreshing only when it has gone stale.

        The cache *refuses* rather than serving a stale reference, so this is a
        deliberate refresh rather than a silent one.
        """
        try:
            return self._tapos.block_ref()
        except RuntimeError:
            return self.refresh_block_ref()

    # -- transaction construction ----------------------------------------

    def finalizeOp(self, ops, account=None, permission="posting", **kwargs):
        """Sign, and broadcast unless ``nobroadcast`` is set.

        ``ops`` is a single ``(name, fields)`` pair or a list of them. beem also
        accepted its own operation objects; pass plain tuples or dicts here.
        """
        if isinstance(ops, tuple) and len(ops) == 2 and isinstance(ops[0], str):
            ops = [ops]
        elif isinstance(ops, dict):
            ops = [(ops["type"].replace("_operation", ""), ops["value"])]
        operations = [_as_operation(op) for op in ops]

        wifs = kwargs.pop("keys", None) or self.wifs
        if not wifs:
            raise ValueError(
                "no signing keys; pass keys=[wif] to Hive() or to this call"
            )

        signed = comb.sign_transaction(
            operations,
            self._block_ref(),
            wifs,
            expiration_seconds=kwargs.pop("expiration", self.expiration),
            chain=self.chain,
        )
        if self.nobroadcast:
            return signed
        return self.broadcast(signed)

    def broadcast(self, tx, trx_id=True):
        """Broadcast a signed transaction and wait for the node to accept it."""
        payload = {k: v for k, v in tx.items() if k != "trx_id"}
        self.rpc.call("network_broadcast_api.broadcast_transaction", {"trx": payload})
        return tx

    def sign(self, tx=None, wifs=None, reconstruct_tx=True):
        raise not_implemented(
            "Hive.sign on a prebuilt transaction",
            "Build and sign in one step with finalizeOp, or use "
            "comb.sign_transaction directly.",
        )

    # -- operations beem had ---------------------------------------------

    def custom_json(
        self,
        id,
        json_data,
        required_auths=None,
        required_posting_auths=None,
        **kwargs,
    ):
        """Broadcast a ``custom_json`` operation."""
        required_auths = list(required_auths or [])
        required_posting_auths = list(required_posting_auths or [])
        if not required_auths and not required_posting_auths:
            raise ValueError(
                "custom_json needs at least one required_auths or "
                "required_posting_auths entry"
            )
        return self.finalizeOp(
            (
                "custom_json",
                {
                    "required_auths": required_auths,
                    "required_posting_auths": required_posting_auths,
                    "id": id,
                    "json": json_data,
                },
            ),
            **kwargs,
        )

    def transfer(self, to, amount, asset, memo="", account=None, **kwargs):
        """Broadcast a ``transfer``."""
        if account is None:
            raise ValueError("transfer needs the sending account")
        return self.finalizeOp(
            (
                "transfer",
                {
                    "from": account,
                    "to": to,
                    "amount": _format_amount(amount, asset),
                    "memo": memo,
                },
            ),
            **kwargs,
        )

    def vote(self, weight, identifier=None, account=None, author=None, permlink=None, **kwargs):
        """Broadcast a ``vote``.

        ``weight`` is a percentage in ``-100.0..=100.0``, as beem takes it.
        """
        if identifier:
            author, permlink = _split_identifier(identifier)
        if not (author and permlink and account):
            raise ValueError("vote needs account, author and permlink")
        return self.finalizeOp(
            (
                "vote",
                {
                    "voter": account,
                    "author": author,
                    "permlink": permlink,
                    "weight": int(round(float(weight) * 100)),
                },
            ),
            **kwargs,
        )

    # -- operations beem could not build ---------------------------------

    def recurrent_transfer(
        self,
        to,
        amount,
        asset,
        recurrence,
        executions,
        memo="",
        account=None,
        pair_id=None,
        **kwargs,
    ):
        """Broadcast a ``recurrent_transfer`` (HF25).

        **Not available in beem**: the operation is absent from its id table, so
        `beem` raises ``ValueError("Unknown operation")``. Its unreachable
        `Recurring_transfer` class also misspells the name, omits `extensions`,
        and types the counters as signed (findings 2 and 22).

        ``pair_id`` is the HF28 extension that lets one account run several
        concurrent recurrent transfers to the same recipient.
        """
        if account is None:
            raise ValueError("recurrent_transfer needs the sending account")
        fields = {
            "from": account,
            "to": to,
            "amount": _format_amount(amount, asset),
            "memo": memo,
            "recurrence": int(recurrence),
            "executions": int(executions),
        }
        if pair_id is not None:
            fields["extensions"] = [[1, {"pair_id": int(pair_id)}]]
        return self.finalizeOp(("recurrent_transfer", fields), **kwargs)

    def collateralized_convert(self, amount, requestid=None, account=None, **kwargs):
        """Broadcast a ``collateralized_convert`` (HF25).

        **Not available in beem**: absent from its id table.
        """
        if account is None:
            raise ValueError("collateralized_convert needs an account")
        return self.finalizeOp(
            (
                "collateralized_convert",
                {
                    "owner": account,
                    "requestid": int(requestid if requestid is not None else time.time()),
                    "amount": _format_amount(amount, "HIVE"),
                },
            ),
            **kwargs,
        )

    def post(self, title, body, author=None, permlink=None, reply_identifier=None,
             json_metadata=None, comment_options=None, community=None, tags=None,
             beneficiaries=None, self_vote=False, parse_body=False, app=None, **kwargs):
        """Broadcast a ``comment``, optionally with ``comment_options``.

        ``reply_identifier`` makes it a reply; without one it is a root post and
        needs a category, taken from ``community`` or the first tag.
        """
        if author is None:
            raise ValueError("post needs an author")
        if reply_identifier:
            parent_author, parent_permlink = _split_identifier(reply_identifier)
        else:
            parent_author = ""
            parent_permlink = community or (tags[0] if tags else "")
            if not parent_permlink:
                raise ValueError("a root post needs a community or at least one tag")
        if permlink is None:
            permlink = _permlink_from(title) if title else f"re-{int(time.time())}"

        metadata = dict(json_metadata or {})
        if tags:
            metadata.setdefault("tags", list(tags))
        if app:
            metadata.setdefault("app", app)

        ops = [
            (
                "comment",
                {
                    "parent_author": parent_author,
                    "parent_permlink": parent_permlink,
                    "author": author,
                    "permlink": permlink,
                    "title": title or "",
                    "body": body,
                    "json_metadata": metadata,
                },
            )
        ]

        if comment_options or beneficiaries:
            options = dict(comment_options or {})
            options.setdefault("author", author)
            options.setdefault("permlink", permlink)
            options.setdefault("max_accepted_payout", "1000000.000 HBD")
            options.setdefault("percent_hbd", 10000)
            options.setdefault("allow_votes", True)
            options.setdefault("allow_curation_rewards", True)
            if beneficiaries:
                options["extensions"] = [[0, {"beneficiaries": beneficiaries}]]
            options.setdefault("extensions", [])
            ops.append(("comment_options", options))

        return self.finalizeOp(ops, **kwargs)

    def comment_options(self, options, identifier, beneficiaries=None, account=None,
                        **kwargs):
        """Broadcast a ``comment_options`` for an existing post."""
        author, permlink = _split_identifier(identifier)
        fields = dict(options or {})
        fields.update({"author": author, "permlink": permlink})
        fields.setdefault("max_accepted_payout", "1000000.000 HBD")
        fields.setdefault("percent_hbd", 10000)
        fields.setdefault("allow_votes", True)
        fields.setdefault("allow_curation_rewards", True)
        if beneficiaries:
            fields["extensions"] = [[0, {"beneficiaries": beneficiaries}]]
        fields.setdefault("extensions", [])
        return self.finalizeOp(("comment_options", fields), **kwargs)

    def delete_comment(self, identifier, account=None, **kwargs):
        author, permlink = _split_identifier(identifier)
        return self.finalizeOp(
            ("delete_comment", {"author": author, "permlink": permlink}), **kwargs
        )

    def claim_account(self, creator, fee="0.000 HIVE", **kwargs):
        """Claim an account creation token."""
        return self.finalizeOp(
            ("claim_account", {"creator": creator, "fee": fee, "extensions": []}),
            **kwargs,
        )

    def create_claimed_account(self, new_account_name, creator, owner_key, active_key,
                               posting_key, memo_key, json_metadata=None, **kwargs):
        """Create an account from a claimed token."""
        def authority(key):
            return {"weight_threshold": 1, "account_auths": [], "key_auths": [[key, 1]]}

        return self.finalizeOp(
            (
                "create_claimed_account",
                {
                    "creator": creator,
                    "new_account_name": new_account_name,
                    "owner": authority(owner_key),
                    "active": authority(active_key),
                    "posting": authority(posting_key),
                    "memo_key": memo_key,
                    "json_metadata": json_metadata or {},
                    "extensions": [],
                },
            ),
            **kwargs,
        )

    def witness_feed_publish(self, base, quote="1.000 HIVE", account=None, **kwargs):
        """Publish a witness price feed."""
        if account is None:
            raise ValueError("feed publishing needs the witness account")
        return self.finalizeOp(
            (
                "feed_publish",
                {
                    "publisher": account,
                    "exchange_rate": {"base": str(base), "quote": str(quote)},
                },
            ),
            **kwargs,
        )

    def decline_voting_rights(self, decline=True, account=None, **kwargs):
        """Irreversibly decline voting rights, after a 30-day delay."""
        if account is None:
            raise ValueError("decline_voting_rights needs an account")
        return self.finalizeOp(
            ("decline_voting_rights", {"account": account, "decline": bool(decline)}),
            **kwargs,
        )

    # -- niceties ---------------------------------------------------------

    def __repr__(self):
        return (
            f"<Hive nodes={len(self.rpc.nodes)} keys={len(self.wifs)} "
            f"nobroadcast={self.nobroadcast}>"
        )


class Steem(Hive):
    """Steem is not supported.

    beem targeted both chains. `comb` targets Hive: the Steem entry in beem's
    chain table carries the all-zero chain id, which is the same trap as
    finding 5.
    """

    def __init__(self, *args, **kwargs):
        raise not_implemented("Steem", "comb targets Hive.")


#: Constructor arguments accepted for compatibility and ignored, because they
#: describe behaviour this implementation does not have (caching layers, appbase
#: negotiation, node ranking that is now the caller's).
_IGNORED_KWARGS = {
    "blocking",
    "bundle",
    "custom_chains",
    "data_refresh_time_seconds",
    "debug",
    "offline",
    "unsigned",
    "use_condenser",
    "appbase",
    "wallet",
    "autoconnect",
}


def _as_operation(op):
    """Normalise one operation into the ``(name, fields)`` pair comb takes."""
    if isinstance(op, tuple) and len(op) == 2:
        return (op[0], dict(op[1]))
    if isinstance(op, list) and len(op) == 2:
        return (op[0], dict(op[1]))
    if isinstance(op, dict) and "type" in op and "value" in op:
        return (op["type"].replace("_operation", ""), dict(op["value"]))
    raise ValueError(f"cannot read {op!r} as an operation")


def _format_amount(amount, asset):
    """Render an amount the way Hive expects, without going through float.

    beem's `Amount` converted through `float()` before reaching `Decimal`,
    losing units past 2**53 — reachable for large VESTS amounts (finding 16).
    Here a string passes through untouched and a number is formatted at the
    asset's precision with `Decimal`.
    """
    from decimal import Decimal

    if isinstance(amount, str):
        return amount if " " in amount else f"{amount} {asset}"
    precision = 6 if asset.upper() == "VESTS" else 3
    quantum = Decimal(1).scaleb(-precision)
    value = Decimal(str(amount)).quantize(quantum)
    return f"{value} {asset}"


def _permlink_from(title):
    """A permlink from a title, the way Hive clients build one."""
    import re as _re

    slug = _re.sub(r"[^a-z0-9]+", "-", str(title).lower()).strip("-")
    return f"{slug[:200] or 'post'}-{int(time.time())}"


def _split_identifier(identifier):
    """Split ``@author/permlink`` into its parts."""
    text = identifier.lstrip("@")
    if "/" not in text:
        raise ValueError(f"{identifier!r} is not an @author/permlink identifier")
    author, permlink = text.split("/", 1)
    return author, permlink
