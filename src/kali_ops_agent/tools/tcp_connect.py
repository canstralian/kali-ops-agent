"""A first real governed tool adapter: a TCP connect probe.

This is the mildest, most defensible recon primitive — a single TCP connect to
one host:port to classify it as open / closed / filtered. It does real network
I/O (unlike :class:`ReconStub`), so it demonstrates the full pattern a
production adapter follows, while staying non-intrusive: it sends no payload and
exploits nothing.

The safety-critical detail is that the host it connects to is derived from the
*same* normalization the governance engine used to scope-check the request
(``scope._target_host``). The adapter can therefore never reach a host other
than the one the engine authorized — a rogue suffix or userinfo trick that the
scope layer already fails closed on cannot smuggle a different destination in
here either.
"""

from __future__ import annotations

import socket
import time

from ..models import AuthorityTier, ToolRequest
from ..scope import _target_host
from .example import GovernedTool


class TcpConnectTool(GovernedTool):
    """Probe one TCP port on an in-scope target.

    Arguments (via ``ToolRequest.arguments``):
        port: the TCP port to probe (required, 1–65535).

    Result: ``{"host", "port", "state", "latency_ms"}`` where ``state`` is one
    of ``open``, ``closed``, ``filtered``, ``invalid-argument``, or ``error``.
    """

    name = "tcp-connect"
    min_tier = AuthorityTier.USER
    # A single connect probe is benign recon; keep it at USER tier and off the
    # approval gate. An engagement that wants sign-off can subclass and set
    # requires_approval = True without touching the governance flow.
    requires_approval = False

    def __init__(self, engine, *, timeout: float = 2.0) -> None:
        super().__init__(engine)
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        self._timeout = timeout

    def _perform(self, request: ToolRequest) -> dict[str, object]:
        host = _target_host(request.target)
        port = self._parse_port(request.arguments.get("port"))
        if not host or port is None:
            return {
                "host": host,
                "port": request.arguments.get("port"),
                "state": "invalid-argument",
                "reason": "a valid target host and port (1-65535) are required",
            }

        start = time.monotonic()
        state = self._probe(host, port)
        latency_ms = round((time.monotonic() - start) * 1000, 2)
        return {"host": host, "port": port, "state": state, "latency_ms": latency_ms}

    def _probe(self, host: str, port: int) -> str:
        try:
            with socket.create_connection((host, port), timeout=self._timeout):
                return "open"
        except ConnectionRefusedError:
            return "closed"
        except TimeoutError:  # socket.timeout is an alias for this
            return "filtered"
        except OSError:
            return "error"

    @staticmethod
    def _parse_port(value: object) -> int | None:
        try:
            port = int(str(value))
        except (TypeError, ValueError):
            return None
        return port if 1 <= port <= 65535 else None
