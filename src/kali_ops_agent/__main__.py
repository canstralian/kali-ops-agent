"""Entry point: ``python -m kali_ops_agent --config engagement.json``."""

from __future__ import annotations

from .server import main

if __name__ == "__main__":
    raise SystemExit(main())
