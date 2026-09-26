"""Engagement scope validation with hard-block on out-of-scope targets.

Scope is an explicit allowlist. Anything not provably inside it is denied — the
default answer is always "no". Supported entry forms:

* an exact hostname (``app.example.com``)
* a CIDR block (``10.0.0.0/24``) matched against literal IP targets
* a URL, matched by host

There is no wildcard-everything entry and no "disable scope" switch by design;
broadening scope means adding a specific, auditable entry.
"""

from __future__ import annotations

import ipaddress
from urllib.parse import urlparse

from .errors import ScopeError


def _target_host(target: str) -> str:
    """Extract a comparable host from a host, URL, or IP string.

    Handles bare hosts, ``host:port``, scheme-prefixed URLs, and bracketed
    IPv6 literals (``[::1]`` / ``[::1]:8443``). ``urlparse`` already unwraps
    the brackets on scheme-prefixed IPv6 URLs; the explicit handling below
    covers the bracketed forms that arrive without a scheme.
    """
    candidate = target.strip()
    if "://" in candidate:
        parsed = urlparse(candidate)
        candidate = parsed.hostname or ""
    elif candidate.startswith("["):
        # Bracketed IPv6, optionally with a trailing :port after the bracket.
        end = candidate.find("]")
        if end != -1:
            candidate = candidate[1:end]
    elif candidate.count(":") == 1 and not _is_ipv6(candidate):
        # Bare host:port form (a single colon that is not itself an IPv6 addr).
        candidate = candidate.rsplit(":", 1)[0]
    return candidate.lower().rstrip(".")


def _is_ipv6(value: str) -> bool:
    try:
        return isinstance(ipaddress.ip_address(value), ipaddress.IPv6Address)
    except ValueError:
        return False


def _matches_entry(host: str, entry: str) -> bool:
    entry = entry.strip().lower().rstrip(".")
    if not entry:
        return False
    # CIDR entry: only meaningful for literal-IP targets.
    if "/" in entry:
        try:
            network = ipaddress.ip_network(entry, strict=False)
            return ipaddress.ip_address(host) in network
        except ValueError:
            return False
    return host == entry


class ScopeGuard:
    """Holds the authorized scope for one engagement and answers membership."""

    def __init__(self, allowed: list[str]) -> None:
        # Store non-empty, normalized entries. An empty allowlist denies all.
        self._allowed = [e.strip() for e in allowed if e and e.strip()]

    @property
    def entries(self) -> list[str]:
        return list(self._allowed)

    def contains(self, target: str) -> bool:
        host = _target_host(target)
        if not host:
            return False
        return any(_matches_entry(host, entry) for entry in self._allowed)

    def enforce(self, target: str) -> None:
        """Raise unless ``target`` is inside the authorized scope.

        Raises:
            ScopeError: if the target is out of scope (the hard block).
        """
        if not self.contains(target):
            raise ScopeError(
                f"target '{target}' is not within the authorized engagement scope"
            )
