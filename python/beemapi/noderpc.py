"""JSON-RPC access.

Drop-in for `beemapi.noderpc.NodeRPC`. Uses only the standard library, so the
compatibility layer adds no dependencies; beem pulled in `requests` and
`websocket-client`.

Unknown attributes proxy to `condenser_api` methods, as beem's did, so
``rpc.get_accounts([["alice"]])`` keeps working. Pass ``api="database_api"`` to
reach another namespace.
"""

from comb_compat import NodeClient, RPCError

__all__ = ["NodeRPC", "RPCError"]


class NodeRPC(NodeClient):
    """A JSON-RPC client with node failover."""

    def __init__(self, urls=None, num_retries=3, timeout=10, **kwargs):
        super().__init__(nodes=urls, timeout=timeout, num_retries=num_retries)

    def get_use_appbase(self):
        """Always true: every node this talks to is appbase."""
        return True

    def set_next_node_on_empty_reply(self, *args, **kwargs):
        """Accepted and ignored.

        beem used this to steer its own node rotation. Failover here is
        automatic and per call, so there is nothing to set.
        """
        return None
