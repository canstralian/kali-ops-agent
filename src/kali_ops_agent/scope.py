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
from urllib.parse import urlsplit

from .errors import ScopeError


def _target_host(target: str) -> str:
    """Extract the real host from a host, ``host:port``, URL, or IP string.

    The whole target is parsed as a URL authority — bare or scheme-relative
    forms are given a ``//`` prefix — so that userinfo, ports, and bracketed
    IPv6 literals all resolve to the *actual* host. This is the security-
    critical part: a naive ``split(":")`` would read ``in-scope:22@out-of-scope``
    as the in-scope left-hand side, letting an out-of-scope authority ride past
    the allowlist while the raw target string still points at the real host.
    Parsing the authority resolves such a string to ``out-of-scope`` instead.

    Any malformed authority (an unterminated IPv6 bracket, a non-numeric port,
    a bracketed non-IP) raises during parsing and is failed closed by returning
    ``""``, which matches no allowlist entry.
    """
    candidate = target.strip()
    if not candidate:
        return ""
    # A bare, unbracketed IP literal (v4 or v6) is used directly; urlsplit would
    # otherwise misread an unbracketed IPv6 address's colons as a port.
    if _is_ip(candidate):
        return candidate.lower()
    scheme_prefixed = "://" in candidate
    to_parse = candidate if scheme_prefixed else "//" + candidate
    try:
        parts = urlsplit(to_parse)
        host = parts.hostname or ""
        _ = parts.port  # raises ValueError on a non-numeric / out-of-range port
    except ValueError:
        return ""
    # A schemeless target must be a bare authority (host[:port]). If urlsplit
    # peeled off a path/query/fragment, the input was not a clean authority —
    # e.g. a CIDR like "10.0.0.0/24" whose "/24" would be silently dropped, or
    # a "host/path" form — so fail closed instead of matching the bare host.
    # (CIDR *range* targets are handled explicitly in ScopeGuard.contains.)
    if not scheme_prefixed and (parts.path or parts.query or parts.fragment):
        return ""
    return host.lower().rstrip(".")


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _as_network(value: str):
    """Return the ip_network for an explicit CIDR target, else None.

    Only a value carrying an explicit prefix ("/") is treated as a range; a
    bare address is a single host, matched through the host path instead.
    """
    if "/" not in value:
        return None
    try:
        return ipaddress.ip_network(value, strict=False)
    except ValueError:
        return None


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


def _entry_contains_network(entry: str, network) -> bool:
    """Whether an allowlist CIDR entry fully contains ``network`` (a range target)."""
    entry = entry.strip()
    try:
        entry_net = ipaddress.ip_network(entry, strict=False)
    except ValueError:
        return False
    if entry_net.version != network.version:
        return False
    return network.subnet_of(entry_net)


class ScopeGuard:
    """Holds the authorized scope for one engagement and answers membership."""

    def __init__(self, allowed: list[str]) -> None:
        # Store non-empty, normalized entries. An empty allowlist denies all.
        self._allowed = [e.strip() for e in allowed if e and e.strip()]

    @property
    def entries(self) -> list[str]:
        return list(self._allowed)

    def contains(self, target: str) -> bool:
        # A CIDR *range* target (e.g. "10.0.0.0/24") is in scope only if the
        # whole range is contained in an allowlisted network. This is the guard
        # against range-smuggling: "10.0.0.5/0" must not pass just because its
        # base address would.
        network = _as_network(target.strip())
        if network is not None:
            return any(_entry_contains_network(entry, network) for entry in self._allowed)
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
