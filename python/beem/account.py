"""Accounts.

Drop-in for `beem.account.Account`. Subclasses :class:`dict`, as beem's did, so
``account["balance"]`` and ``account.name`` both work.

**What differs.** beem's `Account` could reach the network on attribute access,
which is the design that puts a node call in unexpected places. This one fetches
when you construct or :meth:`refresh` it, and never otherwise. Mana and RC are
extrapolated locally, so :meth:`get_voting_power` costs nothing.

Post-HF25 fields beem predates are available: ``governance_vote_expiration_ts``,
``open_recurrent_transfers``, ``previous_owner_update``.
"""

from __future__ import annotations

import json as _json
import time
from datetime import datetime, timedelta, timezone

from .amount import Amount
from .exceptions import AccountDoesNotExistsException, MissingKeyError
from .instance import BlockchainInstance

__all__ = ["Account", "Accounts", "AccountsObject"]

#: Seconds for a mana bar to refill from empty to full.
VOTING_MANA_REGENERATION_SECONDS = 432_000


def _now():
    return int(time.time())


#: hived renders ``time_point_sec::maximum()`` -- all bits set -- as this, because
#: its JSON formatter prints a ``uint32`` as though it were a signed ``int32``. It
#: means "never", not a date in 1969.
NEVER = "1969-12-31T23:59:59"


def _parse_time(value):
    """Parse hived's timestamp form.

    Returns ``None`` for the "never" sentinel. Reading it as an actual 1969
    datetime is the trap: every comparison then says the deadline has passed,
    so ``governance_votes_expired()`` would report every account as expired.
    """
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    text = str(value).rstrip("Z")
    if text == NEVER:
        return None
    return datetime.strptime(text, "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)


class Account(dict):
    """A Hive account."""

    def __init__(self, account, full=True, lazy=False, **kwargs):
        self._instance = BlockchainInstance(**kwargs)
        self.full = full
        if isinstance(account, dict):
            super().__init__(account)
            self.name = account.get("name", "")
        else:
            self.name = str(account).strip().lstrip("@")
            super().__init__()
            if not lazy:
                self.refresh()

    # -- fetching ----------------------------------------------------------

    @property
    def blockchain(self):
        return self._instance.blockchain

    steem = blockchain
    hive = blockchain

    def refresh(self):
        """Re-fetch from the node."""
        result = self.blockchain.rpc.call(
            "condenser_api.get_accounts", [[self.name]]
        )
        if not result:
            raise AccountDoesNotExistsException(f"account {self.name!r} does not exist")
        self.clear()
        self.update(result[0])
        self.name = self["name"]
        return self

    def json(self):
        return dict(self)

    # -- identity ----------------------------------------------------------

    def __repr__(self):
        return f"<Account {self.name}>"

    @property
    def profile(self):
        """The parsed profile, or ``{}``.

        Both metadata fields are free-form strings that are often empty or not
        valid JSON, so this never raises.
        """
        for field in ("posting_json_metadata", "json_metadata"):
            raw = self.get(field) or ""
            if not raw:
                continue
            try:
                parsed = _json.loads(raw)
            except ValueError:
                continue
            if isinstance(parsed, dict):
                return parsed.get("profile", parsed)
        return {}

    @property
    def json_metadata(self):
        raw = self.get("json_metadata") or ""
        try:
            return _json.loads(raw) if raw else {}
        except ValueError:
            return {}

    @property
    def posting_json_metadata(self):
        raw = self.get("posting_json_metadata") or ""
        try:
            return _json.loads(raw) if raw else {}
        except ValueError:
            return {}

    @property
    def rep(self):
        return self.get_reputation()

    def get_reputation(self):
        """Reputation on the familiar 25–75 scale."""
        raw = self.get("reputation", 0)
        try:
            raw = int(raw)
        except (TypeError, ValueError):
            return 25.0
        if raw == 0:
            return 25.0
        import math

        score = max(math.log10(abs(raw)) - 9, 0)
        if raw < 0:
            score = -score
        return score * 9 + 25

    # -- balances ----------------------------------------------------------

    def _amount(self, field):
        value = self.get(field)
        return Amount(value) if value is not None else None

    @property
    def available_balances(self):
        return [
            self._amount("balance"),
            self._amount("hbd_balance"),
            self._amount("vesting_shares"),
        ]

    @property
    def saving_balances(self):
        return [self._amount("savings_balance"), self._amount("savings_hbd_balance")]

    @property
    def reward_balances(self):
        return [
            self._amount("reward_hive_balance"),
            self._amount("reward_hbd_balance"),
            self._amount("reward_vesting_balance"),
        ]

    @property
    def total_balances(self):
        totals = []
        for available, saving in zip(self.available_balances[:2], self.saving_balances):
            totals.append(available + saving if available and saving else available)
        totals.append(self._amount("vesting_shares"))
        return totals

    @property
    def balances(self):
        return self.get_balances()

    def get_balances(self):
        return {
            "available": [b for b in self.available_balances if b],
            "savings": [b for b in self.saving_balances if b],
            "rewards": [b for b in self.reward_balances if b],
            "total": [b for b in self.total_balances if b],
        }

    def get_balance(self, balances, symbol):
        """One balance by group and symbol."""
        if isinstance(balances, str):
            balances = self.get_balances().get(balances, [])
        symbol = symbol.upper()
        for amount in balances:
            if amount and amount.symbol == symbol:
                return amount
        return Amount(0, symbol)

    # -- vesting -----------------------------------------------------------

    def get_vests(self, only_own_vests=False):
        """Effective VESTS: owned, minus delegated out, plus received.

        This is what determines vote weight. It is **not** ``vesting_shares`` —
        an account that has delegated most of its stake away still shows the
        full amount there.
        """
        own = Amount(self["vesting_shares"])
        if only_own_vests:
            return own
        return own - Amount(self["delegated_vesting_shares"]) + Amount(
            self["received_vesting_shares"]
        )

    get_effective_vesting_shares = get_vests

    def get_token_power(self, only_own_vests=False):
        """Effective VESTS converted to HIVE, using the chain's current ratio."""
        props = self.blockchain.get_dynamic_global_properties()
        fund = Amount(props["total_vesting_fund_hive"])
        total = Amount(props["total_vesting_shares"])
        if total.units() == 0:
            return Amount(0, "HIVE")
        vests = self.get_vests(only_own_vests)
        # Integer maths throughout: VESTS totals are ~10^17 units and a float
        # would lose digits.
        units = vests.units() * fund.units() // total.units()
        return Amount({"amount": str(units), "precision": 3, "nai": "@@000000021"})

    #: beem's older names for the same thing.
    sp = property(lambda self: self.get_token_power())
    tp = property(lambda self: self.get_token_power())
    get_steem_power = get_token_power

    # -- mana --------------------------------------------------------------

    def get_manabar(self):
        """The voting mana bar, extrapolated to now. No network call."""
        return self._manabar("voting_manabar", self.get_vests().units())

    def get_downvote_manabar(self):
        """The downvote mana bar. Downvote mana is a quarter of vote mana."""
        if "downvote_manabar" not in self:
            return None
        return self._manabar("downvote_manabar", self.get_vests().units() // 4)

    def _manabar(self, field, max_mana):
        bar = self[field]
        elapsed = max(0, _now() - int(bar["last_update_time"]))
        regenerated = (
            min(elapsed, VOTING_MANA_REGENERATION_SECONDS)
            * max_mana
            // VOTING_MANA_REGENERATION_SECONDS
        )
        current = min(max(int(bar["current_mana"]) + regenerated, 0), max_mana)
        # The // and * order matters: current * 100 overflows nothing in Python,
        # but the same expression in a fixed-width language does, so keep the
        # arithmetic exact rather than going via float.
        percentage = (current * 10000 // max_mana) / 100 if max_mana else 0.0
        return {
            "current_mana": current,
            "max_mana": max_mana,
            "current_mana_pct": percentage,
            "last_update_time": int(bar["last_update_time"]),
        }

    def get_voting_power(self, with_regeneration=True):
        """Voting power as a percentage, extrapolated to now."""
        return self.get_manabar()["current_mana_pct"]

    vp = property(get_voting_power)

    def get_downvoting_power(self, with_regeneration=True):
        bar = self.get_downvote_manabar()
        return bar["current_mana_pct"] if bar else 0.0

    def get_rc(self):
        """Resource credits for this account."""
        result = self.blockchain.rpc.call(
            "rc_api.find_rc_accounts", {"accounts": [self.name]}
        )
        accounts = result.get("rc_accounts") or []
        if not accounts:
            raise AccountDoesNotExistsException(f"no RC record for {self.name!r}")
        return accounts[0]

    def get_rc_manabar(self):
        """The RC mana bar, extrapolated to now."""
        rc = self.get_rc()
        max_rc = int(rc["max_rc"])
        bar = rc["rc_manabar"]
        elapsed = max(0, _now() - int(bar["last_update_time"]))
        regenerated = (
            min(elapsed, VOTING_MANA_REGENERATION_SECONDS)
            * max_rc
            // VOTING_MANA_REGENERATION_SECONDS
        )
        current = min(max(int(bar["current_mana"]) + regenerated, 0), max_rc)
        return {
            "current_mana": current,
            "max_mana": max_rc,
            "current_pct": (current * 10000 // max_rc) / 100 if max_rc else 0.0,
            "last_update_time": int(bar["last_update_time"]),
        }

    def get_manabar_recharge_time(self, manabar, recharge_pct_goal=100):
        """When the bar reaches ``recharge_pct_goal``."""
        delta = self.get_manabar_recharge_timedelta(manabar, recharge_pct_goal)
        return datetime.now(timezone.utc) + delta

    def get_manabar_recharge_timedelta(self, manabar, recharge_pct_goal=100):
        missing_pct = max(0.0, recharge_pct_goal - manabar["current_mana_pct"])
        seconds = missing_pct / 100 * VOTING_MANA_REGENERATION_SECONDS
        return timedelta(seconds=int(seconds))

    def get_manabar_recharge_time_str(self, manabar, recharge_pct_goal=100):
        return str(self.get_manabar_recharge_timedelta(manabar, recharge_pct_goal))

    get_recharge_time = get_manabar_recharge_time
    get_recharge_timedelta = get_manabar_recharge_timedelta
    get_recharge_time_str = get_manabar_recharge_time_str

    # -- post-HF25 state ---------------------------------------------------

    @property
    def governance_vote_expiration(self):
        """When this account's governance votes expire, or ``None`` for never.

        Hive expires witness and proposal votes after a year of inactivity
        (HF25). beem predates the field entirely.

        ``None`` means the account has no expiry set — which the chain writes as
        its "never" sentinel, not as a date in the past. See :data:`NEVER`.
        """
        return _parse_time(self.get("governance_vote_expiration_ts"))

    def governance_votes_expired(self, when=None):
        expiry = self.governance_vote_expiration
        if expiry is None:
            return False
        return expiry <= (when or datetime.now(timezone.utc))

    @property
    def open_recurrent_transfers(self):
        """Number of live recurrent transfers.

        beem cannot even build the operation that creates one.
        """
        return int(self.get("open_recurrent_transfers", 0))

    # -- history -----------------------------------------------------------

    def history(self, start=None, stop=None, limit=1000, only_ops=None, exclude_ops=None,
                batch_size=1000, raw_output=False):
        """Iterate operations oldest-first.

        Yields the ``op`` payload of each history entry, with ``index``,
        ``block``, ``timestamp`` and ``trx_id`` merged in, as beem did.
        """
        yield from self._history(reverse=False, limit=limit, only_ops=only_ops,
                                 exclude_ops=exclude_ops, batch_size=batch_size,
                                 raw_output=raw_output)

    def history_reverse(self, start=None, stop=None, limit=1000, only_ops=None,
                        exclude_ops=None, batch_size=1000, raw_output=False):
        """Iterate operations newest-first."""
        yield from self._history(reverse=True, limit=limit, only_ops=only_ops,
                                 exclude_ops=exclude_ops, batch_size=batch_size,
                                 raw_output=raw_output)

    def _history(self, reverse, limit, only_ops, exclude_ops, batch_size, raw_output):
        only_ops = set(only_ops or [])
        exclude_ops = set(exclude_ops or [])
        batch_size = max(1, min(int(batch_size), 1000))
        collected = []
        cursor = -1
        remaining = limit

        while remaining > 0:
            take = min(batch_size, remaining, 1000)
            entries = self.blockchain.rpc.call(
                "condenser_api.get_account_history", [self.name, cursor, take - 1]
            )
            if not entries:
                break
            for index, entry in entries:
                op_type, op_value = entry["op"]
                if only_ops and op_type not in only_ops:
                    continue
                if op_type in exclude_ops:
                    continue
                if raw_output:
                    collected.append((index, entry))
                else:
                    record = dict(op_value)
                    record.update(
                        {
                            "type": op_type,
                            "index": index,
                            "block": entry.get("block"),
                            "timestamp": entry.get("timestamp"),
                            "trx_id": entry.get("trx_id"),
                        }
                    )
                    collected.append(record)
            oldest = entries[0][0]
            remaining -= len(entries)
            if oldest == 0:
                break
            cursor = max(0, oldest - 1)
            if cursor == 0:
                break

        collected.sort(key=lambda r: r[0] if raw_output else r["index"])
        if reverse:
            collected.reverse()
        yield from collected

    def virtual_op_count(self):
        entries = self.blockchain.rpc.call(
            "condenser_api.get_account_history", [self.name, -1, 0]
        )
        return entries[0][0] if entries else 0

    # -- social ------------------------------------------------------------

    def get_follow_count(self):
        return self.blockchain.rpc.call("condenser_api.get_follow_count", [self.name])

    def get_followers(self, raw_name_list=True, limit=100):
        return self._follow_list("blog", limit, following=False)

    def get_following(self, raw_name_list=True, limit=100):
        return self._follow_list("blog", limit, following=True)

    def get_muters(self, raw_name_list=True, limit=100):
        return self._follow_list("ignore", limit, following=False)

    def get_mutings(self, raw_name_list=True, limit=100):
        return self._follow_list("ignore", limit, following=True)

    def _follow_list(self, what, limit, following):
        method = (
            "condenser_api.get_following" if following else "condenser_api.get_followers"
        )
        entries = self.blockchain.rpc.call(method, [self.name, None, what, limit])
        key = "following" if following else "follower"
        return [entry[key] for entry in entries]

    def get_notifications(self, limit=100, last_id=None):
        return self.blockchain.rpc.call(
            "bridge.account_notifications", {"account": self.name, "limit": limit}
        )

    def get_account_posts(self, sort="feed", limit=20, observer=None):
        return self.blockchain.rpc.call(
            "bridge.get_account_posts",
            {"sort": sort, "account": self.name, "limit": limit},
        )

    get_blog = get_account_posts
    get_feed = get_account_posts

    # -- delegations and requests ------------------------------------------

    def get_vesting_delegations(self, start_account="", limit=100):
        return self.blockchain.rpc.call(
            "condenser_api.get_vesting_delegations", [self.name, start_account, limit]
        )

    def get_expiring_vesting_delegations(self, after=None, limit=100):
        return self.blockchain.rpc.call(
            "condenser_api.get_expiring_vesting_delegations", [self.name, after, limit]
        )

    def get_withdraw_routes(self, withdraw_route_type="all"):
        return self.blockchain.rpc.call(
            "condenser_api.get_withdraw_routes", [self.name, withdraw_route_type]
        )

    def get_conversion_requests(self):
        return self.blockchain.rpc.call(
            "condenser_api.get_conversion_requests", [self.name]
        )

    def get_savings_withdrawals(self, direction="from", limit=100):
        method = (
            "condenser_api.get_savings_withdraw_from"
            if direction == "from"
            else "condenser_api.get_savings_withdraw_to"
        )
        return self.blockchain.rpc.call(method, [self.name])

    def get_owner_history(self):
        return self.blockchain.rpc.call("condenser_api.get_owner_history", [self.name])

    def get_recovery_request(self):
        return self.blockchain.rpc.call(
            "condenser_api.get_recovery_request", [self.name]
        )

    def get_account_votes(self, account=None):
        return self.blockchain.rpc.call(
            "condenser_api.get_account_votes", [account or self.name]
        )

    # -- broadcasting ------------------------------------------------------

    def _broadcast(self, name, fields, **kwargs):
        return self.blockchain.finalizeOp((name, fields), account=self.name, **kwargs)

    def transfer(self, to, amount, asset, memo="", account=None, **kwargs):
        return self.blockchain.transfer(
            to, amount, asset, memo=memo, account=account or self.name, **kwargs
        )

    def recurring_transfer(self, to, amount, asset, recurrence, executions, memo="",
                           account=None, pair_id=None, **kwargs):
        """Set up a recurrent transfer (HF25).

        **beem cannot build this operation**: it is absent from beem's id table.
        """
        return self.blockchain.recurrent_transfer(
            to, amount, asset, recurrence, executions,
            memo=memo, account=account or self.name, pair_id=pair_id, **kwargs
        )

    recurrent_transfer = recurring_transfer

    def transfer_to_vesting(self, amount, to=None, account=None, **kwargs):
        account = account or self.name
        return self._broadcast(
            "transfer_to_vesting",
            {"from": account, "to": to or account, "amount": _fmt(amount, "HIVE")},
            **kwargs,
        )

    def withdraw_vesting(self, amount, account=None, **kwargs):
        account = account or self.name
        return self._broadcast(
            "withdraw_vesting",
            {"account": account, "vesting_shares": _fmt(amount, "VESTS")},
            **kwargs,
        )

    def delegate_vesting_shares(self, to_account, vesting_shares, account=None, **kwargs):
        account = account or self.name
        return self._broadcast(
            "delegate_vesting_shares",
            {
                "delegator": account,
                "delegatee": to_account,
                "vesting_shares": _fmt(vesting_shares, "VESTS"),
            },
            **kwargs,
        )

    def convert(self, amount, account=None, request_id=None, **kwargs):
        account = account or self.name
        return self._broadcast(
            "convert",
            {
                "owner": account,
                "requestid": int(request_id if request_id is not None else _now()),
                "amount": _fmt(amount, "HBD"),
            },
            **kwargs,
        )

    def collateralized_convert(self, amount, account=None, request_id=None, **kwargs):
        """Convert HIVE to HBD immediately against collateral (HF25).

        **beem cannot build this operation.**
        """
        return self.blockchain.collateralized_convert(
            amount, requestid=request_id, account=account or self.name, **kwargs
        )

    def transfer_to_savings(self, amount, asset, memo="", to=None, account=None, **kwargs):
        account = account or self.name
        return self._broadcast(
            "transfer_to_savings",
            {"from": account, "to": to or account, "amount": _fmt(amount, asset), "memo": memo},
            **kwargs,
        )

    def transfer_from_savings(self, amount, asset, memo="", request_id=None, to=None,
                              account=None, **kwargs):
        account = account or self.name
        return self._broadcast(
            "transfer_from_savings",
            {
                "from": account,
                "request_id": int(request_id if request_id is not None else _now()),
                "to": to or account,
                "amount": _fmt(amount, asset),
                "memo": memo,
            },
            **kwargs,
        )

    def cancel_transfer_from_savings(self, request_id, account=None, **kwargs):
        account = account or self.name
        return self._broadcast(
            "cancel_transfer_from_savings",
            {"from": account, "request_id": int(request_id)},
            **kwargs,
        )

    def claim_reward_balance(self, reward_hive=0, reward_hbd=0, reward_vests=0,
                             account=None, **kwargs):
        account = account or self.name
        if not (reward_hive or reward_hbd or reward_vests):
            rewards = self.reward_balances
            reward_hive = rewards[0] or Amount(0, "HIVE")
            reward_hbd = rewards[1] or Amount(0, "HBD")
            reward_vests = rewards[2] or Amount(0, "VESTS")
        return self._broadcast(
            "claim_reward_balance",
            {
                "account": account,
                "reward_hive": _fmt(reward_hive, "HIVE"),
                "reward_hbd": _fmt(reward_hbd, "HBD"),
                "reward_vests": _fmt(reward_vests, "VESTS"),
            },
            **kwargs,
        )

    def set_withdraw_vesting_route(self, to, percentage=100, account=None,
                                   auto_vest=False, **kwargs):
        account = account or self.name
        return self._broadcast(
            "set_withdraw_vesting_route",
            {
                "from_account": account,
                "to_account": to,
                "percent": int(float(percentage) * 100),
                "auto_vest": bool(auto_vest),
            },
            **kwargs,
        )

    def approvewitness(self, witness, account=None, approve=True, **kwargs):
        account = account or self.name
        return self._broadcast(
            "account_witness_vote",
            {"account": account, "witness": witness, "approve": bool(approve)},
            **kwargs,
        )

    def disapprovewitness(self, witness, account=None, **kwargs):
        return self.approvewitness(witness, account=account, approve=False, **kwargs)

    def setproxy(self, proxy="", account=None, **kwargs):
        account = account or self.name
        proxy_name = proxy.name if isinstance(proxy, Account) else str(proxy)
        return self._broadcast(
            "account_witness_proxy", {"account": account, "proxy": proxy_name}, **kwargs
        )

    def follow(self, other, what=None, account=None, **kwargs):
        return self._follow_op(other, ["blog"] if what is None else what, account, **kwargs)

    def unfollow(self, other, account=None, **kwargs):
        return self._follow_op(other, [], account, **kwargs)

    def mute(self, other, account=None, **kwargs):
        return self._follow_op(other, ["ignore"], account, **kwargs)

    def _follow_op(self, other, what, account, **kwargs):
        account = account or self.name
        other_name = other.name if isinstance(other, Account) else str(other)
        payload = ["follow", {"follower": account, "following": other_name, "what": what}]
        return self.blockchain.custom_json(
            "follow", payload, required_posting_auths=[account], **kwargs
        )

    def update_account_profile(self, profile, account=None, **kwargs):
        account = account or self.name
        return self._broadcast(
            "account_update2",
            {
                "account": account,
                "json_metadata": "",
                "posting_json_metadata": _json.dumps(
                    {"profile": profile}, separators=(",", ":")
                ),
                "extensions": [],
            },
            **kwargs,
        )

    update_account_jsonmetadata = update_account_profile

    def update_memo_key(self, key, account=None, **kwargs):
        raise MissingKeyError(
            "changing the memo key needs the active authority and the full "
            "authority set; build it with beembase.operations.Account_update2 "
            "and Hive.finalizeOp"
        )

    def print_info(self, force_refresh=False, return_str=False, use_table=False, **kwargs):
        """A short human-readable summary."""
        power = self.get_token_power()
        lines = [
            f"@{self.name}",
            f"  reputation      {self.get_reputation():.2f}",
            f"  balance         {self.get_balance('available', 'HIVE')}",
            f"  hbd             {self.get_balance('available', 'HBD')}",
            f"  hive power      {power}",
            f"  voting power    {self.get_voting_power():.2f}%",
        ]
        downvote = self.get_downvoting_power()
        if downvote:
            lines.append(f"  downvote power  {downvote:.2f}%")
        if self.open_recurrent_transfers:
            lines.append(f"  recurrent xfers {self.open_recurrent_transfers}")
        text = "\n".join(lines)
        if return_str:
            return text
        print(text)
        return None

    print = print_info


def _fmt(amount, asset):
    """Render an amount for an operation, without going via float."""
    if isinstance(amount, Amount):
        return str(amount)
    if isinstance(amount, str) and " " in amount:
        return amount
    return str(Amount(amount, asset))


class Accounts(list):
    """Several accounts at once."""

    def __init__(self, name_list, batch_limit=100, **kwargs):
        instance = BlockchainInstance(**kwargs)
        names = [str(n).lstrip("@") for n in name_list]
        results = []
        for start in range(0, len(names), batch_limit):
            chunk = names[start : start + batch_limit]
            results.extend(
                instance.blockchain.rpc.call("condenser_api.get_accounts", [chunk])
            )
        super().__init__([Account(raw, **kwargs) for raw in results])


#: beem's name for the same thing.
AccountsObject = Accounts
