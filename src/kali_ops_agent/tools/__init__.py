"""Governed tool adapters.

Each adapter is a thin wrapper that (1) normalizes its inputs into a
``ToolRequest``, (2) asks the ``GovernanceEngine`` for a verdict, and (3) only
performs its real work on ``Decision.ALLOW``. The template in ``example.py``
shows the contract; real offensive-tool adapters are added per engagement and
must never call out before the engine has allowed the request.
"""

from __future__ import annotations

from .example import GovernedTool, ReconStub

__all__ = ["GovernedTool", "ReconStub"]
