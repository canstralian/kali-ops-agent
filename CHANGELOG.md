# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Dependabot configuration (`.github/dependabot.yml`) for weekly `github-actions`
  and `pip` updates, keeping the CI workflow's pinned action SHAs maintained.
- This changelog.

## [0.1.0] - 2026-09-26

Initial baseline — a governance-first MCP framework for authorized purple-team
operations. The control plane is the product; tool adapters plug into it and act
only after a fail-closed `Decision.ALLOW`.

### Added
- **Governance core** (no MCP dependency, fully unit-tested):
  - Four-tier authority hierarchy (System > Developer > User > Embedded).
  - Engagement scope validation with a hard block; targets are parsed as URL
    authorities via `urlsplit`, so userinfo, bare `host:port`, CIDR-range, and
    bracketed-IPv6 smuggling all fail closed. CIDR range targets are allowed
    only when fully contained in an allowlisted network.
  - Per-`(principal, tool)` token-bucket rate limiting; non-finite (NaN/inf)
    values are rejected.
  - HMAC-SHA256 approval tokens bound to the full request payload (tool, target,
    action, arguments, engagement), single-use via a nonce, validated before the
    rate gate and consumed only once a request is fully allowed.
  - Append-only, hash-chained tamper-evident audit log.
  - `GovernanceEngine`: fail-closed pipeline (authority → scope → approval-verify
    → rate → approval-consume) that records every verdict.
- **Surface & tooling**:
  - Thin FastMCP server binding; the principal is bound to the engagement, never
    a client argument.
  - `GovernedTool` base class and the benign `ReconStub` template.
  - `TcpConnectTool` (`tcp_connect`): the first real governed adapter — a
    non-intrusive TCP-port probe that does real I/O confined to the scope-checked
    host.
  - Example engagement configuration under `examples/`.
- **Project**: Apache-2.0 license, README, `SECURITY.md` (authorized-use policy),
  `CONTRIBUTING.md`, `CLAUDE.md` (agent guidance), and GitHub Actions CI
  (ruff + pytest on Python 3.11 and 3.12, least-privilege permissions,
  SHA-pinned actions).

[Unreleased]: https://github.com/canstralian/kali-ops-agent/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/canstralian/kali-ops-agent/releases/tag/v0.1.0
