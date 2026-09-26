# kali-ops-agent

**A governance-first [MCP](https://modelcontextprotocol.io) framework for
authorized purple-team operations.**

This project is a *control plane*, not a toolbox of exploits. It gives an AI
agent (or any MCP client) a way to drive security tooling under enforceable
guardrails: an authority hierarchy, engagement scope validation with a hard
block, token-bucket rate limiting, HMAC approval tokens, and a tamper-evident
audit log. Actual tool adapters are templates you wire up for a **specific,
authorized engagement** — and every one of them is routed through the same
governance engine, so no action can skip the checks.

> ⚠️ **Authorized use only.** See [SECURITY.md](SECURITY.md). Operate only
> against systems you have explicit, documented permission to test.

## Why governance-first

Most "AI + security tooling" glue is a thin wrapper that hands a model a shell.
This inverts that: the guardrails are the product, and tools plug into them.

| Control | Guarantee | Module |
|---|---|---|
| **Authority hierarchy** | System > Developer > User > Embedded; lower tiers never widen higher-tier constraints. Content from tool output is *data*, never a command. | `authority.py` |
| **Scope hard-block** | Targets are an explicit allowlist. Anything not provably in scope is denied. No wildcard, no disable switch. | `scope.py` |
| **Rate budget** | Per-`(principal, tool)` token bucket bounds how much a caller can drive a tool. | `ratelimit.py` |
| **Approval tokens** | High-impact actions require an out-of-band HMAC-SHA256 signature over the exact request. | `approval.py` |
| **Audit log** | Append-only, hash-chained record of every decision. Tampering breaks the chain. | `audit.py` |

The [`GovernanceEngine`](src/kali_ops_agent/engine.py) runs these checks in a
fixed, fail-closed order and records every verdict before returning it.

## Architecture

```
MCP client (e.g. an agent)
        │  tool call
        ▼
   server.py  ── FastMCP surface, no policy of its own
        │  ToolRequest
        ▼
 GovernanceEngine ──►  1. authority   (authority.py)
   (engine.py)         2. scope       (scope.py)      ── hard block
        │              3. rate budget (ratelimit.py)
        │              4. approval     (approval.py)
        │  every decision ─────────────► audit.py  (hash-chained)
        ▼
   ALLOW ⇒ tool._perform(...)   |   DENY / NEEDS_APPROVAL ⇒ no action
```

The core (`models`, `authority`, `scope`, `ratelimit`, `approval`, `audit`,
`engine`) has **no MCP dependency** and is fully unit-tested. `server.py` is a
thin FastMCP binding.

## Quick start

```bash
git clone https://github.com/canstralian/kali-ops-agent
cd kali-ops-agent
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"     # core + test tooling
pytest                       # governance core tests (no MCP needed)
```

### Run the MCP server

```bash
pip install -e ".[server]"                        # adds the mcp runtime
export KALI_OPS_APPROVAL_SECRET="<engagement secret>"   # optional, for approval-gated tools
python -m kali_ops_agent --config examples/engagement.example.json
```

The example engagement authorizes a single lab host and exposes two governed
tools: `recon_stub` (a no-op template that exercises the entire governance path)
and `tcp_connect` — a real, benign recon primitive that probes one TCP port on
an in-scope target (open/closed/filtered) and connects only to the host the
engine authorized. See `src/kali_ops_agent/tools/tcp_connect.py` for the
reference adapter pattern.

### Use the core directly

```python
from kali_ops_agent import (
    GovernanceEngine, ScopeGuard, TokenBucketLimiter, AuditLog,
    Principal, ToolRequest, AuthorityTier, Decision,
)

engine = GovernanceEngine(
    scope=ScopeGuard(["lab.internal"]),
    limiter=TokenBucketLimiter(),
    audit=AuditLog(),
)

principal = Principal(id="op-1", tier=AuthorityTier.USER, engagement_id="eng-1")
verdict = engine.evaluate(principal, ToolRequest(tool="recon-stub", target="lab.internal"))
assert verdict.decision is Decision.ALLOW   # out-of-scope targets return DENY
```

## Adding a real tool adapter

Subclass [`GovernedTool`](src/kali_ops_agent/tools/example.py), declare its
authority and approval requirements, and implement `_perform` — which is only
ever reached after `Decision.ALLOW`:

```python
from kali_ops_agent.tools import GovernedTool
from kali_ops_agent.models import AuthorityTier, ToolRequest

class MyAdapter(GovernedTool):
    name = "my-tool"
    min_tier = AuthorityTier.DEVELOPER
    requires_approval = True

    def _perform(self, request: ToolRequest) -> dict:
        # Authorized invocation goes here. Scope, authority, rate,
        # approval, and audit have all already passed.
        ...
```

The governance flow around it never changes — that is the point.

## Project layout

```
src/kali_ops_agent/
  models.py       Pydantic contracts (Principal, ToolRequest, verdicts)
  authority.py    four-tier authority hierarchy
  scope.py        engagement scope allowlist + hard block
  ratelimit.py    token-bucket safety budget
  approval.py     HMAC-SHA256 approval tokens
  audit.py        append-only hash-chained audit log
  engine.py       the fail-closed check pipeline
  config.py       engagement configuration loading
  server.py       FastMCP binding
  tools/          governed tool adapters (templates)
tests/            unit tests for the governance core
examples/         a sample engagement config
```

## Status

`0.1.0` — alpha scaffold. The governance core and its tests are complete; tool
adapters are intentionally left as templates to be added per engagement.

## License

[Apache 2.0](LICENSE).
