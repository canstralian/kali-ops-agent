"""Engagement configuration.

An engagement is the unit of authorization: a named window with an explicit
target scope, a rate budget, and an approval secret. Configuration is loaded
from a JSON file and/or the environment; nothing here reaches out to a network.

The approval secret is read only from the environment
(``KALI_OPS_APPROVAL_SECRET``) so it never has to live in a checked-in file.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from pydantic import BaseModel, Field

from .ratelimit import BucketConfig

APPROVAL_SECRET_ENV = "KALI_OPS_APPROVAL_SECRET"


class EngagementConfig(BaseModel):
    """Declarative description of one authorized engagement."""

    engagement_id: str = Field(..., min_length=1)
    operator_id: str = Field(
        default="operator",
        min_length=1,
        description="Identity bound to server-issued requests (audit + rate key). "
        "Set per engagement; production should bind to the authenticated session.",
    )
    scope: list[str] = Field(
        default_factory=list,
        description="Authorized targets (hosts, CIDRs, URLs). Empty denies all.",
    )
    # allow_inf_nan=False is essential: Pydantic v2 accepts inf/NaN in float
    # fields by default, and gt=0 does not reject them. A non-finite rate would
    # silently disable the safety budget, so both fields must be finite.
    rate_capacity: float = Field(default=10.0, gt=0, allow_inf_nan=False)
    rate_refill_per_sec: float = Field(default=1.0, gt=0, allow_inf_nan=False)
    audit_path: str | None = Field(
        default=None, description="Optional JSONL path for the persisted audit log."
    )

    def bucket_config(self) -> BucketConfig:
        return BucketConfig(
            capacity=self.rate_capacity, refill_per_sec=self.rate_refill_per_sec
        )

    @classmethod
    def from_file(cls, path: str | Path) -> EngagementConfig:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls.model_validate(data)


def load_approval_secret(*, required: bool = True) -> bytes:
    """Read the approval secret from the environment.

    Args:
        required: if True, a missing secret raises; if False, returns b"" so a
            non-approval workflow can run without it configured.
    """
    raw = os.environ.get(APPROVAL_SECRET_ENV, "")
    if not raw and required:
        raise RuntimeError(
            f"{APPROVAL_SECRET_ENV} is not set; approval-gated actions are unavailable"
        )
    return raw.encode("utf-8")
