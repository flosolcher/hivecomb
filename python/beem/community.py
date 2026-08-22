"""Communities.

Drop-in for `beem.community`. Communities are a Hivemind concept, so everything
here goes through the `bridge` API and through `custom_json` operations with the
``community`` id.
"""

from __future__ import annotations

from .exceptions import ContentDoesNotExistsException
from .instance import BlockchainInstance

__all__ = ["Community", "Communities"]


class Community(dict):
    """A Hive community."""

    def __init__(self, community, observer="", lazy=False, **kwargs):
        self._instance = BlockchainInstance(**kwargs)
        if isinstance(community, dict):
            super().__init__(community)
            self.identifier = community.get("name", "")
        else:
            self.identifier = str(community)
            super().__init__()
            if not lazy:
                self.refresh()

    @property
    def blockchain(self):
        return self._instance.blockchain

    def refresh(self):
        result = self.blockchain.rpc.call(
            "bridge.get_community", {"name": self.identifier, "observer": ""}
        )
        if not result:
            raise ContentDoesNotExistsException(f"community {self.identifier!r} not found")
        self.clear()
        self.update(result)
        return self

    def json(self):
        return dict(self)

    # -- reading -----------------------------------------------------------

    def get_community_roles(self, last="", limit=100):
        return self.blockchain.rpc.call(
            "bridge.list_community_roles", {"community": self.identifier, "limit": limit}
        )

    def get_subscribers(self, last="", limit=100):
        return self.blockchain.rpc.call(
            "bridge.list_subscribers", {"community": self.identifier, "limit": limit}
        )

    def get_activities(self, limit=100):
        return self.blockchain.rpc.call(
            "bridge.account_notifications",
            {"account": self.identifier, "limit": limit},
        )

    def get_ranked_posts(self, sort="trending", limit=20, observer=""):
        return self.blockchain.rpc.call(
            "bridge.get_ranked_posts",
            {"sort": sort, "tag": self.identifier, "limit": limit, "observer": observer},
        )

    # -- writing -----------------------------------------------------------

    def _custom_json(self, action, payload, account, **kwargs):
        body = dict(payload)
        body["community"] = self.identifier
        return self.blockchain.custom_json(
            "community",
            [action, body],
            required_posting_auths=[account],
            **kwargs,
        )

    def set_role(self, account, role, mod_account=None, **kwargs):
        if mod_account is None:
            raise ValueError("set_role needs the moderating account")
        return self._custom_json(
            "setRole", {"account": account, "role": role}, mod_account, **kwargs
        )

    def set_user_title(self, account, title, mod_account=None, **kwargs):
        if mod_account is None:
            raise ValueError("set_user_title needs the moderating account")
        return self._custom_json(
            "setUserTitle", {"account": account, "title": title}, mod_account, **kwargs
        )

    def mute_post(self, account, permlink, notes="", mod_account=None, **kwargs):
        if mod_account is None:
            raise ValueError("mute_post needs the moderating account")
        return self._custom_json(
            "mutePost",
            {"account": account, "permlink": permlink, "notes": notes},
            mod_account,
            **kwargs,
        )

    def unmute_post(self, account, permlink, notes="", mod_account=None, **kwargs):
        if mod_account is None:
            raise ValueError("unmute_post needs the moderating account")
        return self._custom_json(
            "unmutePost",
            {"account": account, "permlink": permlink, "notes": notes},
            mod_account,
            **kwargs,
        )

    def pin_post(self, account, permlink, mod_account=None, **kwargs):
        if mod_account is None:
            raise ValueError("pin_post needs the moderating account")
        return self._custom_json(
            "pinPost", {"account": account, "permlink": permlink}, mod_account, **kwargs
        )

    def unpin_post(self, account, permlink, mod_account=None, **kwargs):
        if mod_account is None:
            raise ValueError("unpin_post needs the moderating account")
        return self._custom_json(
            "unpinPost", {"account": account, "permlink": permlink}, mod_account, **kwargs
        )

    def flag_post(self, account, permlink, notes="", reporter=None, **kwargs):
        if reporter is None:
            raise ValueError("flag_post needs the reporting account")
        return self._custom_json(
            "flagPost",
            {"account": account, "permlink": permlink, "notes": notes},
            reporter,
            **kwargs,
        )

    def update_props(self, title="", about="", is_nsfw=False, description="",
                     flag_text="", mod_account=None, **kwargs):
        if mod_account is None:
            raise ValueError("update_props needs the moderating account")
        props = {
            "title": title,
            "about": about,
            "is_nsfw": bool(is_nsfw),
            "description": description,
            "flag_text": flag_text,
        }
        return self._custom_json("updateProps", {"props": props}, mod_account, **kwargs)

    def subscribe(self, account, **kwargs):
        return self._custom_json("subscribe", {}, account, **kwargs)

    def unsubscribe(self, account, **kwargs):
        return self._custom_json("unsubscribe", {}, account, **kwargs)

    def print(self):
        print(
            f"{self.get('title', self.identifier)} ({self.identifier})\n"
            f"  subscribers {self.get('subscribers', 0)}\n"
            f"  posts       {self.get('num_pending', 0)}\n"
            f"  about       {self.get('about', '')}"
        )

    def __repr__(self):
        return f"<Community {self.identifier}>"


class Communities(list):
    """The community list, ranked."""

    def __init__(self, sort="rank", observer="", limit=100, lazy=False, **kwargs):
        instance = BlockchainInstance(**kwargs)
        result = instance.blockchain.rpc.call(
            "bridge.list_communities", {"sort": sort, "limit": limit, "observer": observer}
        )
        super().__init__(
            Community(raw, blockchain_instance=instance.blockchain) for raw in result or []
        )

    def search_title(self, title):
        needle = title.lower()
        return [c for c in self if needle in str(c.get("title", "")).lower()]
