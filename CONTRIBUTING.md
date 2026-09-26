# Contributing

Thanks for your interest in `kali-ops-agent`.

## Ground rules

- This is tooling for **authorized** security work. Contributions that weaken
  the governance controls (scope hard-block, authority hierarchy, approval
  gating, audit integrity) will not be merged. Extend authorization
  deliberately; never add a bypass.
- Keep the governance core (`src/kali_ops_agent/*.py` excluding `server.py`) free
  of MCP and network dependencies so it stays unit-testable in isolation.

## Development

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest            # run the test suite
ruff check .      # lint
ruff format .     # format
```

## Pull requests

- Add or update tests for any behavior change; governance changes need tests
  proving the control still fails closed.
- Run `pytest` and `ruff check .` locally before opening the PR. CI runs both.
- Keep commits focused and messages descriptive.

## Reporting security issues

See [SECURITY.md](SECURITY.md). Report vulnerabilities privately, not as public
issues.
