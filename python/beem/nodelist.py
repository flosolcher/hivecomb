"""Known Hive API nodes.

Drop-in for `beem.nodelist.NodeList`.

beem shipped a hard-coded list that went stale as nodes came and went. This one
is also a starting point rather than an authority — prefer your own list, and
use :meth:`NodeList.update_nodes` to measure which are actually responding.
"""

from __future__ import annotations

import time

from comb_compat import DEFAULT_NODES, NodeClient, RPCError

__all__ = ["NodeList"]


class NodeList(list):
    """A list of node URLs, with a way to rank them by measured latency."""

    def __init__(self, *args, **kwargs):
        super().__init__(
            {"url": url, "type": "hive", "owner": "", "score": 0} for url in DEFAULT_NODES
        )

    def get_nodes(self, hive=True, exclude_limited=False, dev=False, testnet=False,
                  testnetdev=False, wss=True, https=True, normal=True, appbase=True):
        """The node URLs, best first."""
        ranked = sorted(self, key=lambda n: -n.get("score", 0))
        return [node["url"] for node in ranked]

    get_hive_nodes = get_nodes
    get_steem_nodes = get_nodes

    def get_testnet(self, testnet=True, testnetdev=False):
        return []

    def update_nodes(self, weights=None, blockchain_instance=None, **kwargs):
        """Measure each node and rank by response time.

        beem's version fetched a ranking someone else had published. Measuring
        directly is both simpler and more honest about what "best" means: it is
        whichever node answers *you* fastest, right now.
        """
        for node in self:
            node["score"] = _score(node["url"], kwargs.get("timeout", 5))
        self.sort(key=lambda n: -n.get("score", 0))
        return self

    def ping_node(self, url, timeout=5):
        """Round-trip time in seconds, or ``None`` if the node did not answer."""
        started = time.time()
        try:
            NodeClient([url], timeout=timeout, num_retries=1).call(
                "database_api.get_dynamic_global_properties", {}
            )
        except (RPCError, Exception):
            return None
        return time.time() - started


def _score(url, timeout):
    """Higher is better; unreachable nodes score zero."""
    started = time.time()
    try:
        NodeClient([url], timeout=timeout, num_retries=1).call(
            "database_api.get_dynamic_global_properties", {}
        )
    except Exception:
        return 0
    elapsed = max(time.time() - started, 1e-6)
    return int(1000 / elapsed)
