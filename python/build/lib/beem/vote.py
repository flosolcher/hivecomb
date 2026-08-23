"""Votes.

Drop-in for `beem.vote`.
"""

from __future__ import annotations

from datetime import datetime, timezone

from .comment import construct_authorperm, resolve_authorperm
from .instance import BlockchainInstance

__all__ = ["Vote", "ActiveVotes", "AccountVotes"]


class Vote(dict):
    """One vote on a post."""

    def __init__(self, voter, authorperm=None, lazy=False, **kwargs):
        self._instance = BlockchainInstance(**kwargs)
        if isinstance(voter, dict):
            super().__init__(voter)
            self.voter = voter.get("voter", "")
            self._authorperm = authorperm or voter.get("authorperm", "")
        else:
            self.voter = str(voter).lstrip("@")
            self._authorperm = authorperm or ""
            super().__init__()

    @property
    def authorperm(self):
        return self._authorperm

    @property
    def votee(self):
        if not self._authorperm:
            return ""
        return resolve_authorperm(self._authorperm)[0]

    @property
    def weight(self):
        return self.get("weight", 0)

    @property
    def rshares(self):
        return int(self.get("rshares", 0) or 0)

    @property
    def percent(self):
        """Vote percentage, in ``-100.0..=100.0``."""
        return self.get("percent", 0) / 100.0

    @property
    def time(self):
        stamp = self.get("time") or self.get("last_update")
        if not stamp:
            return None
        return datetime.strptime(str(stamp).rstrip("Z"), "%Y-%m-%dT%H:%M:%S").replace(
            tzinfo=timezone.utc
        )

    @property
    def rep(self):
        return self.get("reputation", 0)

    reputation = rep

    def json(self):
        return dict(self)

    def __repr__(self):
        return f"<Vote {self.voter} on {self._authorperm} at {self.percent}%>"


class ActiveVotes(list):
    """Every vote on one post."""

    def __init__(self, authorperm, lazy=False, **kwargs):
        instance = BlockchainInstance(**kwargs)
        if isinstance(authorperm, dict):
            votes = authorperm.get("active_votes", [])
            key = construct_authorperm(
                authorperm.get("author", ""), authorperm.get("permlink", "")
            )
        else:
            author, permlink = resolve_authorperm(authorperm)
            key = construct_authorperm(author, permlink)
            votes = instance.blockchain.rpc.call(
                "condenser_api.get_active_votes", [author, permlink]
            )
        super().__init__(
            Vote(vote, authorperm=key, blockchain_instance=instance.blockchain)
            for vote in votes or []
        )

    def get_sorted_list(self, sort_key="rshares", reverse=True):
        return sorted(self, key=lambda v: v.get(sort_key, 0), reverse=reverse)

    def print_stats(self):
        print(f"{len(self)} votes, {sum(v.rshares for v in self)} total rshares")


class AccountVotes(list):
    """Every vote an account has cast."""

    def __init__(self, account, start=None, stop=None, raw_data=False, lazy=False, **kwargs):
        instance = BlockchainInstance(**kwargs)
        name = str(account).lstrip("@")
        votes = instance.blockchain.rpc.call("condenser_api.get_account_votes", [name])
        super().__init__(
            Vote(
                dict(vote, voter=name),
                authorperm=vote.get("authorperm"),
                blockchain_instance=instance.blockchain,
            )
            for vote in votes or []
        )
