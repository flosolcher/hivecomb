"""beem, re-implemented on `comb`.

Installing this distribution in place of `beem` makes existing `import beem`
code work unchanged, with the defects in ``SECURITY_FINDINGS.md`` fixed
underneath and the post-HF25 operations beem never gained made available.

Coverage, divergences and additions are documented in ``MIGRATION.md``. Nothing
here silently does something different from what you asked: anything not
implemented raises :class:`NotImplementedError` naming what to use instead.
"""

from .hive import Hive, Steem
from .instance import (
    set_shared_blockchain_instance,
    shared_blockchain_instance,
    clear_shared_blockchain_instance,
)
from .version import version as __version__

__all__ = [
    "Hive",
    "Steem",
    "set_shared_blockchain_instance",
    "shared_blockchain_instance",
    "clear_shared_blockchain_instance",
    "__version__",
]


def __getattr__(name):
    """Expose the wrapper modules lazily.

    Importing them eagerly would make ``import beem`` pull in every wrapper,
    and several of them reach for a blockchain instance on first use.
    """
    import importlib

    modules = {
        "account": "beem.account",
        "amount": "beem.amount",
        "block": "beem.block",
        "blockchain": "beem.blockchain",
        "comment": "beem.comment",
        "community": "beem.community",
        "discussions": "beem.discussions",
        "exceptions": "beem.exceptions",
        "market": "beem.market",
        "memo": "beem.memo",
        "nodelist": "beem.nodelist",
        "price": "beem.price",
        "rc": "beem.rc",
        "transactionbuilder": "beem.transactionbuilder",
        "vote": "beem.vote",
        "wallet": "beem.wallet",
        "witness": "beem.witness",
    }
    if name in modules:
        return importlib.import_module(modules[name])
    raise AttributeError(f"module 'beem' has no attribute {name!r}")
