# CLAUDE.md

Guidance for Claude Code (and other agents) working in this repository.

## What this project is

`kali-ops-agent` is a **governance-first MCP framework for authorized
purple-team operations**. It is a *control plane*, not a toolbox of exploits:
the guardrails are the product, and tool adapters plug into them. Every action a
tool would take is routed through one fail-closed decision point.

> ⚠️ **Authorized use only.** See `SECURITY.md`. Never weaken a control to make
> something work — widen the *authorization* (add a scope entry, raise the
> caller's tier deliberately) instead. Tool adapters must do real work only
> after the engine returns `Decision.ALLOW`, and only against the scoped target.

## Commands

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"          # core + test/lint tooling
pytest                            # full suite (no network required)
ruff check .                      # lint (must be clean)
ruff format .                     # format

pip install -e ".[server]"        # adds the FastMCP runtime (mcp>=1.2.0,<2)
python -m kali_ops_agent --config examples/engagement.example.json   # run the server
```

CI (`.github/workflows/ci.yml`) runs `ruff check` + `pytest --cov` on Python
3.11 and 3.12. Keep both green before pushing.

## Architecture

The governance **core** has no MCP dependency and is fully unit-tested. The MCP
server is a thin binding with no policy of its own.

```
MCP client → server.py → GovernanceEngine.evaluate()
                              1. authority   (authority.py)
                              2. scope       (scope.py)      ── hard block
                              3. approval     (approval.py)  ── verify; consume LAST
                              4. rate budget (ratelimit.py)
                          every decision → audit.py (hash-chained)
                          ALLOW ⇒ tool._perform(...)  else no action
```

| File | Responsibility |
|---|---|
| `models.py` | Pydantic contracts: `Principal`, `ToolRequest`, `Decision`, `GovernanceResult`, `AuthorityTier` |
| `authority.py` | Four-tier hierarchy: System > Developer > User > Embedded |
| `scope.py` | Engagement allowlist + hard block; `_target_host` normalizes via `urlsplit` so userinfo/CIDR/IPv6 tricks fail closed |
| `ratelimit.py` | Per-`(principal, tool)` token bucket; rejects non-finite values |
| `approval.py` | HMAC-SHA256 tokens: `verify()` is side-effect-free; `consume()` spends the single-use nonce |
| `audit.py` | Append-only, hash-chained log; `verify()` detects tampering |
| `engine.py` | The fail-closed pipeline; records every verdict |
| `config.py` | `EngagementConfig` (scope, rate, operator id); approval secret from `KALI_OPS_APPROVAL_SECRET` |
| `server.py` | FastMCP binding; principal is bound to the engagement, never a client argument |
| `tools/` | Governed adapters (`GovernedTool` base, `ReconStub` template, `TcpConnectTool`) |

## The one invariant

**No tool acts before the engine allows it, and only against the scoped host.**
Concretely:

- Order in `engine.evaluate` is fixed and fail-closed: authority → scope →
  approval (validate) → rate → approval (consume) → ALLOW. Do not reorder
  without understanding why consumption is last (a rate-denied request must not
  burn an approval token).
- Approval tokens bind the **full** request payload (tool, target, action,
  arguments, engagement) and are single-use. Never drop a field from the binding.
- Adapters derive their target host from `scope._target_host(request.target)`,
  the *same* normalization the engine scope-checked — so an adapter can never
  reach a host other than the authorized one.

## Adding a tool adapter

Subclass `GovernedTool`, declare its authority/approval requirements, and
implement `_perform` (reached only on `Decision.ALLOW`). Use `TcpConnectTool`
(`tools/tcp_connect.py`) as the reference for a real adapter that does I/O:

```python
from kali_ops_agent.tools import GovernedTool
from kali_ops_agent.models import AuthorityTier, ToolRequest
from kali_ops_agent.scope import _target_host

class MyAdapter(GovernedTool):
    name = "my-tool"
    min_tier = AuthorityTier.DEVELOPER
    requires_approval = True          # gate high-impact actions

    def _perform(self, request: ToolRequest) -> dict:
        host = _target_host(request.target)   # the authorized host, always
        ...                                    # authorized invocation here
```

Then register it in `tools/__init__.py` and wire a `@mcp.tool()` in `server.py`
that constructs the request and returns `adapter.run(principal, target, ...)`.
Add tests covering: the happy path, out-of-scope denial (assert no I/O happens),
and any argument validation. Prefer loopback / fixtures over real network I/O in
tests.

## Conventions

- **Commits:** Conventional Commits — `<type>(<scope>): <subject>`
  (`feat`, `fix`, `chore`, `docs`, `refactor`, `test`, `ci`, `perf`, `build`).
- **Never commit** engagement scope files (`engagement.json`, `*.local.json`),
  secrets, or audit logs — they are git-ignored.
- **Tests are the contract** for governance behavior. A change to a control
  needs a test proving it still fails closed.
- Keep the core free of MCP/network imports so it stays testable in isolation.

## Safety boundary (for the agent itself)

This repo is dual-use security infrastructure. When extending it, stay on the
defensive/governance side: build controls, benign recon primitives, and
adapters that are gated and audited. Do not add turnkey exploitation, payload
delivery, or anything that bypasses the engine. If a request would weaken the
hard block or the audit trail, stop and confirm intent.
