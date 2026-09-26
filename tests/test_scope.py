import pytest

from kali_ops_agent.errors import ScopeError
from kali_ops_agent.scope import ScopeGuard


def test_exact_host_in_scope():
    guard = ScopeGuard(["app.example.com"])
    assert guard.contains("app.example.com")
    guard.enforce("https://app.example.com/login")


def test_out_of_scope_is_hard_blocked():
    guard = ScopeGuard(["app.example.com"])
    assert not guard.contains("evil.example.net")
    with pytest.raises(ScopeError):
        guard.enforce("evil.example.net")


def test_empty_allowlist_denies_everything():
    guard = ScopeGuard([])
    assert not guard.contains("anything.local")
    with pytest.raises(ScopeError):
        guard.enforce("anything.local")


def test_cidr_matches_literal_ip():
    guard = ScopeGuard(["10.0.0.0/24"])
    assert guard.contains("10.0.0.5")
    assert not guard.contains("10.0.1.5")


def test_bracketed_ipv6_targets_normalize():
    guard = ScopeGuard(["::1", "2001:db8::/32"])
    assert guard.contains("[::1]")
    assert guard.contains("[::1]:8443")
    assert guard.contains("http://[::1]:8080/health")
    assert guard.contains("[2001:db8::5]")
    assert not guard.contains("[2001:dead::5]")


def test_malformed_bracketed_targets_fail_closed():
    guard = ScopeGuard(["::1"])
    # A rogue suffix after the bracket must not ride in on an in-scope inner addr.
    assert not guard.contains("[::1]evil.example.com")
    assert not guard.contains("[::1]@evil.example.com")
    assert not guard.contains("[::1]:80x")
    # Unterminated bracket and a non-IP inner value are both denied.
    assert not guard.contains("[::1")
    assert not guard.contains("[example.com]")


def test_host_port_and_url_forms_normalize():
    guard = ScopeGuard(["target.internal"])
    assert guard.contains("target.internal:8443")
    assert guard.contains("http://target.internal:8080/api")


def test_case_and_trailing_dot_insensitive():
    guard = ScopeGuard(["Target.Example.COM."])
    assert guard.contains("target.example.com")
