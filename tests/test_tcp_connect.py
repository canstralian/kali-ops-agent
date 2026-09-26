import socket
from contextlib import closing

import pytest

from kali_ops_agent.audit import AuditLog
from kali_ops_agent.engine import GovernanceEngine
from kali_ops_agent.models import AuthorityTier, Principal
from kali_ops_agent.ratelimit import BucketConfig, TokenBucketLimiter
from kali_ops_agent.scope import ScopeGuard
from kali_ops_agent.tools import TcpConnectTool


def _engine(scope):
    return GovernanceEngine(
        scope=ScopeGuard(list(scope)),
        limiter=TokenBucketLimiter(BucketConfig(capacity=50, refill_per_sec=50)),
        audit=AuditLog(),
    )


def _principal():
    return Principal(id="op-1", tier=AuthorityTier.USER, engagement_id="eng-1")


@pytest.fixture
def listening_port():
    """A real TCP listener on loopback; yields its bound port."""
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as srv:
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        yield srv.getsockname()[1]


def _find_closed_port():
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]  # closed as soon as the socket is released


def test_open_port_is_detected(listening_port):
    tool = TcpConnectTool(_engine(["127.0.0.1"]))
    result = tool.run(_principal(), "127.0.0.1", arguments={"port": str(listening_port)})
    assert result["ok"] is True
    assert result["result"]["state"] == "open"
    assert result["result"]["port"] == listening_port


def test_closed_port_is_detected():
    tool = TcpConnectTool(_engine(["127.0.0.1"]), timeout=1.0)
    result = tool.run(_principal(), "127.0.0.1", arguments={"port": str(_find_closed_port())})
    assert result["ok"] is True
    assert result["result"]["state"] == "closed"


def test_out_of_scope_target_is_denied_and_no_connection_made(listening_port):
    # Scope allows only example.com; a loopback probe must be blocked by the
    # engine before _perform runs.
    tool = TcpConnectTool(_engine(["app.example.com"]))
    result = tool.run(_principal(), "127.0.0.1", arguments={"port": str(listening_port)})
    assert result["ok"] is False
    assert result["decision"] == "deny"
    assert "result" not in result


def test_invalid_port_is_reported():
    tool = TcpConnectTool(_engine(["127.0.0.1"]))
    for bad in ("0", "70000", "not-a-port", ""):
        result = tool.run(_principal(), "127.0.0.1", arguments={"port": bad})
        assert result["ok"] is True
        assert result["result"]["state"] == "invalid-argument"


def test_probe_targets_only_the_scoped_host(listening_port):
    # A userinfo-smuggling target resolves out of scope, so it is denied and no
    # connection is attempted to the loopback listener embedded in the string.
    tool = TcpConnectTool(_engine(["app.example.com"]))
    result = tool.run(
        _principal(),
        "app.example.com@127.0.0.1",
        arguments={"port": str(listening_port)},
    )
    assert result["ok"] is False
    assert result["decision"] == "deny"
