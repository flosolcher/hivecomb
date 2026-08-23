"""Posts and comments.

Drop-in for `beem.comment.Comment`. Subclasses :class:`dict`, as beem's did.
"""

from __future__ import annotations

import json as _json
from datetime import datetime, timezone

from .amount import Amount
from .exceptions import ContentDoesNotExistsException
from .instance import BlockchainInstance

__all__ = ["Comment", "RecentReplies", "RecentByPath"]


def resolve_authorperm(identifier):
    """Split ``@author/permlink`` (or ``author/permlink``) into its parts."""
    text = str(identifier).strip().lstrip("@")
    if "/" not in text:
        raise ValueError(f"{identifier!r} is not an @author/permlink identifier")
    author, permlink = text.split("/", 1)
    return author, permlink


def construct_authorperm(author, permlink=None):
    if permlink is None:
        return str(author)
    return f"@{author}/{permlink}"


class Comment(dict):
    """A post or a reply."""

    def __init__(self, authorperm, api="bridge", observer="", lazy=False, **kwargs):
        self._instance = BlockchainInstance(**kwargs)
        if isinstance(authorperm, dict):
            super().__init__(authorperm)
            self.author = authorperm.get("author", "")
            self.permlink = authorperm.get("permlink", "")
        else:
            self.author, self.permlink = resolve_authorperm(authorperm)
            super().__init__()
            if not lazy:
                self.refresh()

    @property
    def blockchain(self):
        return self._instance.blockchain

    def refresh(self):
        result = self.blockchain.rpc.call(
            "bridge.get_post", {"author": self.author, "permlink": self.permlink}
        )
        if not result:
            raise ContentDoesNotExistsException(f"{self.authorperm} does not exist")
        self.clear()
        self.update(result)
        return self

    def json(self):
        return dict(self)

    # -- identity ----------------------------------------------------------

    @property
    def authorperm(self):
        return construct_authorperm(self.author, self.permlink)

    @property
    def id(self):
        return self.get("post_id")

    @property
    def category(self):
        return self.get("category", "")

    @property
    def parent_author(self):
        return self.get("parent_author", "")

    @property
    def parent_permlink(self):
        return self.get("parent_permlink", "")

    @property
    def depth(self):
        return self.get("depth", 0)

    @property
    def title(self):
        return self.get("title", "")

    @property
    def body(self):
        return self.get("body", "")

    @property
    def json_metadata(self):
        raw = self.get("json_metadata")
        if isinstance(raw, dict):
            return raw
        try:
            return _json.loads(raw) if raw else {}
        except ValueError:
            return {}

    @property
    def is_main_post(self):
        return not self.parent_author

    @property
    def is_comment(self):
        return bool(self.parent_author)

    @property
    def is_pending(self):
        """Whether the payout window is still open."""
        payout = self.get("payout", 0)
        return not self.get("is_paidout", False) and float(payout or 0) >= 0

    @property
    def reward(self):
        """Total payout so far."""
        return Amount(self.get("payout", 0), "HBD")

    def time_elapsed(self):
        created = self.get("created")
        if not created:
            return None
        when = datetime.strptime(str(created).rstrip("Z"), "%Y-%m-%dT%H:%M:%S").replace(
            tzinfo=timezone.utc
        )
        return datetime.now(timezone.utc) - when

    # -- related content ---------------------------------------------------

    def get_votes(self, raw_data=False):
        return self.get("active_votes", [])

    def get_replies(self, raw_data=False):
        replies = self.blockchain.rpc.call(
            "bridge.get_discussion", {"author": self.author, "permlink": self.permlink}
        )
        if not replies:
            return []
        return [
            Comment(value, blockchain_instance=self.blockchain)
            for key, value in replies.items()
            if key != self.authorperm.lstrip("@")
        ]

    get_all_replies = get_replies

    def get_reblogged_by(self):
        return self.get("reblogged_by", [])

    def get_parent(self):
        if self.is_main_post:
            return self
        return Comment(
            construct_authorperm(self.parent_author, self.parent_permlink),
            blockchain_instance=self.blockchain,
        )

    def get_beneficiaries_pct(self):
        """Total beneficiary share, in percent."""
        total = sum(b.get("weight", 0) for b in self.get("beneficiaries", []))
        return total / 100.0

    # -- broadcasting ------------------------------------------------------

    def vote(self, weight, account=None, **kwargs):
        if account is None:
            raise ValueError("vote needs the voting account")
        return self.blockchain.vote(
            weight, account=account, author=self.author, permlink=self.permlink, **kwargs
        )

    def upvote(self, weight=100, voter=None, **kwargs):
        return self.vote(abs(float(weight)), account=voter, **kwargs)

    def downvote(self, weight=100, voter=None, **kwargs):
        return self.vote(-abs(float(weight)), account=voter, **kwargs)

    def reply(self, body, title="", author=None, meta=None, **kwargs):
        if author is None:
            raise ValueError("reply needs the replying account")
        permlink = f"re-{self.permlink}-{int(datetime.now(timezone.utc).timestamp())}"
        return self.blockchain.post(
            title,
            body,
            author=author,
            permlink=permlink,
            reply_identifier=self.authorperm,
            json_metadata=meta,
            **kwargs,
        )

    def edit(self, body, meta=None, replace=False, **kwargs):
        return self.blockchain.post(
            self.title,
            body,
            author=self.author,
            permlink=self.permlink,
            reply_identifier=(
                construct_authorperm(self.parent_author, self.parent_permlink)
                if self.is_comment
                else None
            ),
            json_metadata=meta if meta is not None else self.json_metadata,
            category=self.category,
            **kwargs,
        )

    def delete(self, account=None, **kwargs):
        account = account or self.author
        return self.blockchain.finalizeOp(
            ("delete_comment", {"author": self.author, "permlink": self.permlink}),
            account=account,
            **kwargs,
        )

    def resteem(self, identifier=None, account=None, **kwargs):
        if account is None:
            raise ValueError("resteem needs the reblogging account")
        payload = [
            "reblog",
            {"account": account, "author": self.author, "permlink": self.permlink},
        ]
        return self.blockchain.custom_json(
            "reblog", payload, required_posting_auths=[account], **kwargs
        )

    def __repr__(self):
        return f"<Comment {self.authorperm}>"


class RecentReplies(list):
    """Replies to an account's posts."""

    def __init__(self, author, skip_own=True, lazy=False, **kwargs):
        instance = BlockchainInstance(**kwargs)
        posts = instance.blockchain.rpc.call(
            "bridge.get_account_posts",
            {"sort": "replies", "account": str(author).lstrip("@"), "limit": 20},
        )
        super().__init__(
            Comment(post, blockchain_instance=instance.blockchain)
            for post in posts or []
            if not (skip_own and post.get("author") == author)
        )


class RecentByPath(list):
    """Posts from a ranked feed, e.g. ``trending`` or ``hot``."""

    def __init__(self, path="promoted", category=None, lazy=False, limit=20, **kwargs):
        instance = BlockchainInstance(**kwargs)
        posts = instance.blockchain.rpc.call(
            "bridge.get_ranked_posts",
            {"sort": path, "tag": category or "", "limit": limit, "observer": ""},
        )
        super().__init__(
            Comment(post, blockchain_instance=instance.blockchain) for post in posts or []
        )
