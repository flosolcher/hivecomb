"""Shared plumbing for the beem compatibility layer.

The `beem`, `beemgraphenebase`, `beembase` and `beemapi` packages in this
distribution re-implement beem's public API on top of `hivecomb`, the Rust library.
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
have checked your code does not rely on them; the Rust and native-Python `hivecomb`
APIs redact by default.

**Coverage is the API that gets used, not all 33k lines.**  Anything not
implemented raises :class:`NotImplementedError` naming what to use instead —
never a silent wrong answer.
"""

from __future__ import annotations

import json
import os
import time
import threading
import urllib.error
import urllib.request

import hivecomb

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
    message = f"hivecomb's beem compatibility layer does not implement {what}."
    if instead:
        message += f" {instead}"
    message += " See MIGRATION.md for the coverage table."
    return NotImplementedError(message)



class HealthPolicy:
    """How aggressively to deprioritise a node that is failing or behind.

    The defaults mirror the Rust client's, which mirror dhive's — the only
    field-tested numbers available for this.
    """

    def __init__(
        self,
        node_cooldown=30.0,
        api_cooldown=60.0,
        failures_before_cooldown=3,
        api_failures_before_cooldown=2,
        stale_block_threshold=30,
        head_block_ttl=120.0,
    ):
        self.node_cooldown = node_cooldown
        self.api_cooldown = api_cooldown
        self.failures_before_cooldown = failures_before_cooldown
        self.api_failures_before_cooldown = api_failures_before_cooldown
        self.stale_block_threshold = stale_block_threshold
        self.head_block_ttl = head_block_ttl


class _NodeState:
    __slots__ = (
        "consecutive_failures",
        "streak_methods",
        "cooldown_until",
        "method_failures",
        "method_cooldown_until",
        "head_block",
        "head_seen_at",
    )

    def __init__(self):
        self.consecutive_failures = 0
        self.streak_methods = set()
        self.cooldown_until = 0.0
        self.method_failures = {}
        self.method_cooldown_until = {}
        self.head_block = None
        self.head_seen_at = 0.0


class HealthTracker:
    """Remembers which nodes are failing, so a dead one is not tried first forever.

    The same design as the Rust client's, and the same two rules that matter:

    * **Order changes; the set never does.** No node is removed, so a period in
      which every node is unwell still tries every node — just in the order
      least likely to waste time. A tracker that could exclude a node is one
      that can turn a partial outage into a total one.
    * **A whole-node cooldown needs failures across more than one method.**
      A node serving everything but one API is a partial node, not a broken
      one, and cooling it entirely would make the per-method tracking useless
      in the exact case it exists for.
    """

    def __init__(self, node_count, policy=None):
        self.policy = policy or HealthPolicy()
        self._state = [_NodeState() for _ in range(node_count)]
        self._lock = threading.Lock()

    def _fresh_head(self, state, now):
        if state.head_block is None:
            return None
        if now - state.head_seen_at > self.policy.head_block_ttl:
            return None
        return state.head_block

    def order(self, method):
        """Indices to try, best first. Always every index, exactly once."""
        now = time.monotonic()
        with self._lock:
            heads = [self._fresh_head(s, now) for s in self._state]
            best = max([h for h in heads if h is not None], default=None)
            tiers = []
            for i, state in enumerate(self._state):
                if state.cooldown_until > now:
                    tier = 3
                elif state.method_cooldown_until.get(method, 0.0) > now:
                    tier = 2
                elif (
                    best is not None
                    and heads[i] is not None
                    and best - heads[i] > self.policy.stale_block_threshold
                ):
                    tier = 1
                else:
                    tier = 0
                tiers.append((tier, i))
        # Stable, so the configured order survives within a tier.
        tiers.sort(key=lambda pair: pair[0])
        return [i for _, i in tiers]

    def record_success(self, index, method):
        with self._lock:
            if not 0 <= index < len(self._state):
                return
            state = self._state[index]
            state.consecutive_failures = 0
            state.streak_methods.clear()
            state.cooldown_until = 0.0
            state.method_failures.pop(method, None)
            state.method_cooldown_until.pop(method, None)

    def record_failure(self, index, method):
        now = time.monotonic()
        with self._lock:
            if not 0 <= index < len(self._state):
                return
            state = self._state[index]
            state.consecutive_failures += 1
            state.streak_methods.add(method)
            # More than one method, or it is a missing API rather than a bad node.
            if (
                state.consecutive_failures >= self.policy.failures_before_cooldown
                and len(state.streak_methods) > 1
            ):
                state.cooldown_until = now + self.policy.node_cooldown
            hits = state.method_failures.get(method, 0) + 1
            state.method_failures[method] = hits
            if hits >= self.policy.api_failures_before_cooldown:
                state.method_cooldown_until[method] = now + self.policy.api_cooldown

    def observe_head_block(self, index, head_block):
        now = time.monotonic()
        with self._lock:
            if 0 <= index < len(self._state):
                self._state[index].head_block = head_block
                self._state[index].head_seen_at = now

    def snapshot(self):
        """What is believed about each node, in node-list order."""
        now = time.monotonic()
        with self._lock:
            heads = [self._fresh_head(s, now) for s in self._state]
            best = max([h for h in heads if h is not None], default=None)
            return [
                {
                    "consecutive_failures": s.consecutive_failures,
                    "in_cooldown": s.cooldown_until > now,
                    "cooling_methods": sorted(
                        m for m, t in s.method_cooldown_until.items() if t > now
                    ),
                    "head_block": heads[i],
                    "stale": (
                        best is not None
                        and heads[i] is not None
                        and best - heads[i] > self.policy.stale_block_threshold
                    ),
                }
                for i, s in enumerate(self._state)
            ]


def _head_block_of(result):
    """The head block a result carries, if it carries one."""
    if isinstance(result, dict):
        value = result.get("head_block_number")
        if isinstance(value, int):
            return value
    return None


class NodeClient:
    """A small JSON-RPC client with node failover.

    Uses only the standard library, so the compatibility layer adds no
    dependencies beyond `hivecomb` itself. beem pulled in `requests` and
    `websocket-client`.
    """

    def __init__(
        self, nodes=None, timeout=10, num_retries=3, initial_backoff=0.25, health=None
    ):
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
        #: Seconds to wait before the second pass over the node list; doubles
        #: each pass, capped at 30s. Set to 0 to fail fast, which is what a call
        #: on a deadline wants.
        self.initial_backoff = initial_backoff
        #: Set to a :class:`HealthPolicy` to remember which nodes are failing and
        #: try them last. Off by default: walking the list from the front is
        #: predictable and is the right mechanism for a caller with failover
        #: policy of its own. Turn it on for a long-running process, where the
        #: default means a dead first node costs its full timeout on every call.
        #: beem has no equivalent, so this is an addition rather than a
        #: compatibility feature -- the default keeps beem's behaviour.
        self.health = HealthTracker(len(nodes), health) if health is not None else None
        self._id = 0
        self._lock = threading.Lock()

    def _next_id(self):
        with self._lock:
            self._id += 1
            return self._id

    def _call_order(self, method):
        """Indices to try. Without health tracking, the configured order."""
        if self.health is None:
            return range(len(self.nodes))
        return self.health.order(method)

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
        for attempt in range(self.num_retries):
            if attempt and self.initial_backoff:
                # Exponential backoff between passes over the whole list, capped
                # so a long retry budget cannot become an unbounded sleep.
                wait = min(self.initial_backoff * (2 ** (attempt - 1)), 30.0)
                time.sleep(wait)
                failures.append(f"(retry pass {attempt + 1} after {wait:.2f}s)")
            for index in self._call_order(method):
                node = self.nodes[index]
                try:
                    request = urllib.request.Request(
                        node,
                        data=payload,
                        headers={
                            "Content-Type": "application/json",
                            "User-Agent": f"hivecomb-compat/{hivecomb.__version__}",
                        },
                    )
                    with urllib.request.urlopen(request, timeout=self.timeout) as response:
                        body = json.loads(response.read().decode("utf-8"))
                except (urllib.error.URLError, OSError, ValueError) as exc:
                    if self.health:
                        self.health.record_failure(index, method)
                    failures.append(f"{node}: {exc}")
                    continue

                if "error" in body and body["error"] is not None:
                    # A node that answers with a protocol-level error answered:
                    # the fault is in the request, not the node, and counting it
                    # against the node would cool the whole list for one bad call.
                    error = body["error"]
                    raise RPCError(
                        f"{method} failed: {error.get('message', error)} "
                        f"(code {error.get('code')})"
                    )
                if "result" not in body:
                    if self.health:
                        self.health.record_failure(index, method)
                    failures.append(f"{node}: response carried neither result nor error")
                    continue
                if self.health:
                    self.health.record_success(index, method)
                    head = _head_block_of(body["result"])
                    if head is not None:
                        self.health.observe_head_block(index, head)
                return body["result"]

        raise RPCError(
            f"all {len(self.nodes)} node(s) failed for {method} over "
            f"{self.num_retries} pass(es) — " + "; ".join(failures)
        )

    def race(self, method, params=None, width=3):
        """Call ``method`` on several nodes **at once** and take the first answer.

        Sequential failover has a worst case of *the sum of the timeouts*: three
        sick nodes at ten seconds each is thirty seconds before the fourth is
        tried. Racing has a worst case of **one** timeout.

        That difference is the reason this exists: a transaction that misses its
        expiration window is lost, and public Hive nodes go unresponsive often
        enough for this to be a routine failure rather than a rare one.

        :meth:`call` is still the default everywhere, because racing costs the
        network `width` times the requests. Reach for this when latency matters
        more, which usually means a deadline.

        **Safe for reads unconditionally.** Safe for broadcasting an
        already-signed transaction, because the chain deduplicates by
        transaction id — the same signed bytes arriving at three nodes are
        accepted once. It is *not* safe to race two differently-signed
        transactions for the same intent: different expirations mean different
        ids and both can land.

        Uses threads rather than asyncio, so it works unchanged in beem's
        synchronous world. The Rust side has an async equivalent.
        """
        from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait

        width = max(1, min(int(width), len(self.nodes)))
        if width == 1:
            return self.call(method, params)

        payload = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": self._next_id(),
                "method": method,
                "params": params if params is not None else {},
            }
        ).encode("utf-8")

        # The healthiest `width` nodes rather than the first `width`: a slot
        # spent on a node known to be down is a slot not spent racing.
        nodes = [self.nodes[i] for i in list(self._call_order(method))[:width]]
        failures = []
        with ThreadPoolExecutor(max_workers=width) as pool:
            futures = {pool.submit(self._post, node, payload): node for node in nodes}
            pending = set(futures)
            while pending:
                done, pending = wait(pending, return_when=FIRST_COMPLETED)
                for future in done:
                    node = futures[future]
                    try:
                        return future.result()
                    except Exception as exc:  # noqa: BLE001 - collected below
                        failures.append(f"{node}: {exc}")
            # Losing requests are abandoned here; the executor shuts down without
            # waiting, so a hung node does not hold up the caller.
        raise RPCError(
            f"all {width} raced node(s) failed for {method} — " + "; ".join(failures)
        )

    def _post(self, node, payload):
        """One request to one node. Raises on anything short of a result."""
        request = urllib.request.Request(
            node,
            data=payload,
            headers={
                "Content-Type": "application/json",
                "User-Agent": f"hivecomb-compat/{hivecomb.__version__}",
            },
        )
        with urllib.request.urlopen(request, timeout=self.timeout) as response:
            body = json.loads(response.read().decode("utf-8"))
        if body.get("error"):
            error = body["error"]
            raise RPCError(
                f"{error.get('message', error)} (code {error.get('code')})"
            )
        if "result" not in body:
            raise RPCError("response carried neither result nor error")
        return body["result"]

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
