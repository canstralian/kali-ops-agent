"""FastMCP server exposing the governed tool surface.

The MCP surface is intentionally thin: it constructs the governance engine from
an :class:`EngagementConfig`, registers governed tools, and forwards calls. All
policy lives in the core modules, so the server has no way to bypass a check —
it can only ask the engine and relay the verdict.

Run with::

    python -m kali_ops_agent --config engagement.json
"""

from __future__ import annotations

from .approval import ApprovalAuthority
from .audit import AuditLog
from .config import EngagementConfig, load_approval_secret
from .engine import GovernanceEngine
from .models import AuthorityTier, Principal
from .ratelimit import TokenBucketLimiter
from .scope import ScopeGuard
from .tools import ReconStub, TcpConnectTool


def build_engine(config: EngagementConfig) -> GovernanceEngine:
    """Assemble a governance engine from an engagement config."""
    approvals: ApprovalAuthority | None = None
    secret = load_approval_secret(required=False)
    if secret:
        approvals = ApprovalAuthority(secret)
    return GovernanceEngine(
        scope=ScopeGuard(config.scope),
        limiter=TokenBucketLimiter(config.bucket_config()),
        audit=AuditLog(config.audit_path),
        approvals=approvals,
    )


def create_server(config: EngagementConfig):
    """Build the FastMCP server. Imports FastMCP lazily so the core stays usable
    without the optional MCP dependency installed.
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError as exc:  # pragma: no cover - exercised only without the dep
        raise RuntimeError(
            "the 'mcp' package is required to run the server; "
            "install with 'pip install kali-ops-agent[server]'"
        ) from exc

    engine = build_engine(config)
    recon = ReconStub(engine)
    tcp_connect_tool = TcpConnectTool(engine)
    mcp = FastMCP("kali-ops-agent")

    # The principal is bound to the server's engagement context, NOT taken from a
    # tool argument. A client-supplied identity would be spoofable: a caller could
    # rotate it to reset its own rate-limit bucket and mis-attribute audit entries,
    # defeating the limiter's whole purpose. A production deployment should derive
    # this identity from the authenticated MCP session/transport rather than the
    # single configured operator used here.
    principal = Principal(
        id=config.operator_id,
        tier=AuthorityTier.USER,
        engagement_id=config.engagement_id,
    )

    @mcp.tool()
    def recon_stub(target: str, action: str = "default") -> dict:
        """Governed reconnaissance template (no-op). Demonstrates the full policy
        path: authority, scope hard-block, approval, rate budget, and audit.
        Replace with a real, authorized adapter per engagement.
        """
        return recon.run(principal, target, action=action)

    @mcp.tool()
    def tcp_connect(target: str, port: int) -> dict:
        """Probe one TCP port on an in-scope target (open/closed/filtered).

        A benign, non-intrusive recon primitive: it performs a single TCP
        connect and sends no payload. The target is scope-checked by the
        governance engine, and the probe connects only to that authorized host.
        """
        return tcp_connect_tool.run(principal, target, arguments={"port": str(port)})

    return mcp


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(prog="kali-ops-agent")
    parser.add_argument(
        "--config", required=True, help="Path to the engagement config JSON file."
    )
    args = parser.parse_args(argv)

    config = EngagementConfig.from_file(args.config)
    server = create_server(config)
    server.run()
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
