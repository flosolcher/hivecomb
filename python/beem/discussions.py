"""Post listings.

Drop-in for `beem.discussions`. beem had a class per sort order; the `bridge`
API has since collapsed most of them into ``get_ranked_posts``, so they are thin
wrappers over that.
"""

from __future__ import annotations

from .comment import Comment
from .instance import BlockchainInstance

__all__ = [
    "Query",
    "Discussions",
    "Discussions_by_trending",
    "Discussions_by_hot",
    "Discussions_by_created",
    "Discussions_by_promoted",
    "Discussions_by_payout",
    "Discussions_by_blog",
    "Discussions_by_feed",
    "Discussions_by_comments",
    "Discussions_by_author_before_date",
]


class Query(dict):
    """The query beem's discussion classes took."""

    def __init__(self, limit=20, tag="", truncate_body=0, start_author=None,
                 start_permlink=None, observer=None, **kwargs):
        super().__init__(
            {
                "limit": limit,
                "tag": tag,
                "truncate_body": truncate_body,
                "start_author": start_author,
                "start_permlink": start_permlink,
                "observer": observer,
            }
        )
        self.update(kwargs)


class _Ranked(list):
    """Shared base: one `bridge.get_ranked_posts` call."""

    sort = "trending"

    def __init__(self, discussion_query=None, lazy=False, **kwargs):
        instance = BlockchainInstance(**kwargs)
        query = discussion_query or Query()
        params = {
            "sort": self.sort,
            "tag": query.get("tag") or "",
            "limit": int(query.get("limit") or 20),
            "observer": query.get("observer") or "",
        }
        if query.get("start_author"):
            params["start_author"] = query["start_author"]
            params["start_permlink"] = query.get("start_permlink") or ""
        posts = instance.blockchain.rpc.call("bridge.get_ranked_posts", params)
        super().__init__(
            Comment(post, blockchain_instance=instance.blockchain) for post in posts or []
        )


class Discussions_by_trending(_Ranked):
    sort = "trending"


class Discussions_by_hot(_Ranked):
    sort = "hot"


class Discussions_by_created(_Ranked):
    sort = "created"


class Discussions_by_promoted(_Ranked):
    sort = "promoted"


class Discussions_by_payout(_Ranked):
    sort = "payout"


class _AccountPosts(list):
    """Shared base: one `bridge.get_account_posts` call."""

    sort = "blog"

    def __init__(self, discussion_query=None, lazy=False, **kwargs):
        instance = BlockchainInstance(**kwargs)
        query = discussion_query or Query()
        account = query.get("tag") or query.get("account") or ""
        posts = instance.blockchain.rpc.call(
            "bridge.get_account_posts",
            {
                "sort": self.sort,
                "account": str(account).lstrip("@"),
                "limit": int(query.get("limit") or 20),
            },
        )
        super().__init__(
            Comment(post, blockchain_instance=instance.blockchain) for post in posts or []
        )


class Discussions_by_blog(_AccountPosts):
    sort = "blog"


class Discussions_by_feed(_AccountPosts):
    sort = "feed"


class Discussions_by_comments(_AccountPosts):
    sort = "comments"


class Discussions_by_author_before_date(_AccountPosts):
    """Posts by one author.

    The ``before_date`` filter beem passed to `tags_api` is gone from `bridge`;
    page with ``start_author``/``start_permlink`` instead.
    """

    sort = "posts"


class Discussions:
    """A façade over the sorts, as beem's was."""

    def __init__(self, lazy=False, **kwargs):
        self._kwargs = kwargs

    def get_discussions(self, discussion_type, discussion_query, limit=1000, **kwargs):
        table = {
            "trending": Discussions_by_trending,
            "hot": Discussions_by_hot,
            "created": Discussions_by_created,
            "promoted": Discussions_by_promoted,
            "payout": Discussions_by_payout,
            "blog": Discussions_by_blog,
            "feed": Discussions_by_feed,
            "comments": Discussions_by_comments,
        }
        if discussion_type not in table:
            raise ValueError(
                f"unknown discussion type {discussion_type!r}; "
                f"known: {sorted(table)}"
            )
        return table[discussion_type](discussion_query, **self._kwargs)
