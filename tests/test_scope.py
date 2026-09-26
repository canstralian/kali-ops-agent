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


def test_userinfo_authority_cannot_smuggle_out_of_scope_host():
    guard = ScopeGuard(["lab.internal", "10.10.0.0/24"])
    # The residual authority (after the userinfo '@') is the REAL host and is
    # out of scope; the in-scope-looking left-hand side must not grant access.
    assert not guard.contains("lab.internal:22@evil.com")
    assert not guard.contains("10.10.0.5:22@evil.com")
    assert not guard.contains("http://lab.internal:22@evil.com/x")
    # A genuine in-scope host:port is still allowed.
    assert guard.contains("lab.internal:22")
    assert guard.contains("10.10.0.5:8443")


def test_malformed_bracketed_targets_fail_closed():
    guard = ScopeGuard(["::1"])
    # A rogue suffix after the bracket must not ride in on an in-scope inner addr.
    assert not guard.contains("[::1]evil.example.com")
    assert not guard.contains("[::1]@evil.example.com")
    assert not guard.contains("[::1]:80x")
    # Unterminated bracket and a non-IP inner value are both denied.
    assert not guard.contains("[::1")
    assert not guard.contains("[example.com]")


def test_scheme_prefixed_bracketed_ipv6_cannot_smuggle_a_host():
    guard = ScopeGuard(["::1"])
    # Same bypass class as the schemeless form, via a URL: the rogue suffix
    # after `]` must not let the target match on the inner `::1`, and a
    # malformed URL must fail closed rather than raise out of _target_host.
    assert not guard.contains("http://[::1]evil.example.com/")
    assert not guard.contains("http://[::1/")
    assert not guard.contains("http://[::1]:80x/")
    # A genuine in-scope bracketed URL is still allowed.
    assert guard.contains("http://[::1]:8080/health")


def test_host_port_and_url_forms_normalize():
    guard = ScopeGuard(["target.internal"])
    assert guard.contains("target.internal:8443")
    assert guard.contains("http://target.internal:8080/api")


def test_case_and_trailing_dot_insensitive():
    guard = ScopeGuard(["Target.Example.COM."])
    assert guard.contains("target.example.com")
