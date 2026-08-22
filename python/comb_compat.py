"""Shared plumbing for the beem compatibility layer.

The `beem`, `beemgraphenebase`, `beembase` and `beemapi` packages in this
distribution re-implement beem's public API on top of `comb`, the Rust library.
Installing this distribution in place of `beem` makes existing `import beem`
code work unchanged, with the defects listed in ``SECURITY_FINDINGS.md`` fixed
underneath.

What that means in practice is documented in ``MIGRATION.md``. Two points matter
enough to repeat here:

**Secrets still render, because beem's do.**  ``repr(PrivateKey)`` returns the
raw private scalar and ``str(PrivateKey)`` returns the WIF, exactly as beem
does, because real code depends on both.  That is finding 9, and the shim
reproduces it *deliberately* so that a drop-in replacement is actually a drop-in.
Set ``COMB_COMPAT_REDACT_KEYS=1`` to switch both to a redacted form once you
have checked your code does not rely on them; the Rust and native-Python `comb`
APIs redact by default.

**Coverage is the API that gets used, not all 33k lines.**  Anything not
implemented raises :class:`NotImplementedError` naming what to use instead —
never a silent wrong answer.
"""

from __future__ import annotations

import json
import os
import threading
import urllib.error
import urllib.request

import comb

__all__ = [
    "REDACT_KEYS",
    "DEFAULT_NODES",
    "NodeClient",
    "RPCError",
    "not_implemented",
]

#: Whether to redact private keys in ``repr``/``str``.
#:
#: Off by default so the shim matches beem, which is what makes it a drop-in.
REDACT_KEYS = os.environ.get("COMB_COMPAT_REDACT_KEYS", "").lower() in {"1", "true", "yes"}

DEFAULT_NODES = [
    "https://api.hive.blog",
    "https://api.deathwing.me",
    "https://hive-api.arcange.eu",
    "https://api.openhive.network",
    "https://techcoderx.com",
    "https://api.syncad.com",
]


class RPCError(Exception):
    """A JSON-RPC call failed on every node, or the node returned an error."""


def not_implemented(what: str, instead: str = "") -> "NotImplementedError":
    """Build a clear refusal.

    A shim that silently returns the wrong thing is worse than one that stops.
    Every gap says what is missing and what to do about it.
    """
    message = f"comb's beem compatibility layer does not implement {what}."
    if instead:
        message += f" {instead}"
    message += " See MIGRATION.md for the coverage table."
    return NotImplementedError(message)


class NodeClient:
    """A small JSON-RPC client with node failover.

    Uses only the standard library, so the compatibility layer adds no
    dependencies beyond `comb` itself. beem pulled in `requests` and
    `websocket-client`.
    """

    def __init__(self, nodes=None, timeout=10, num_retries=3):
        if nodes is None:
            nodes = list(DEFAULT_NODES)
        elif isinstance(nodes, str):
            nodes = [nodes]
        else:
            nodes = list(nodes)
        if not nodes:
            raise ValueError("node list is empty")
        self.nodes = nodes
        self.timeout = timeout
        self.num_retries = max(1, num_retries)
        self._id = 0
        self._lock = threading.Lock()

    def _next_id(self):
        with self._lock:
            self._id += 1
            return self._id

    def call(self, method, params=None):
        """Call ``method``, trying each node in turn.

        The raised error names every node that failed and why, rather than only
        the last one — diagnosing "all nodes failed" from one message is one of
        the things that makes node trouble hard to read.
        """
        payload = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": self._next_id(),
                "method": method,
                "params": params if params is not None else {},
            }
        ).encode("utf-8")

        failures = []
        for _ in range(self.num_retries):
            for node in self.nodes:
                try:
                    request = urllib.request.Request(
                        node,
                        data=payload,
                        headers={
                            "Content-Type": "application/json",
                            "User-Agent": f"comb-compat/{comb.__version__}",
                        },
                    )
                    with urllib.request.urlopen(request, timeout=self.timeout) as response:
                        body = json.loads(response.read().decode("utf-8"))
                except (urllib.error.URLError, OSError, ValueError) as exc:
                    failures.append(f"{node}: {exc}")
                    continue

                if "error" in body and body["error"] is not None:
                    error = body["error"]
                    raise RPCError(
                        f"{method} failed: {error.get('message', error)} "
                        f"(code {error.get('code')})"
                    )
                if "result" not in body:
                    failures.append(f"{node}: response carried neither result nor error")
                    continue
                return body["result"]

        raise RPCError(
            f"all {len(self.nodes)} node(s) failed for {method} — " + "; ".join(failures)
        )

    # beem's NodeRPC proxies unknown attributes to RPC methods. Keeping that
    # makes call sites like `rpc.get_dynamic_global_properties()` work.
    def __getattr__(self, name):
        if name.startswith("_"):
            raise AttributeError(name)

        def method(*args, **kwargs):
            api = kwargs.pop("api", None)
            full = f"{api}.{name}" if api else f"condenser_api.{name}"
            return self.call(full, list(args) if args else [])

        return method
