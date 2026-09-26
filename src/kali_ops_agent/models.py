"""Pydantic v2 data models shared across the governance layer.

These models are the wire contract between the MCP tool surface and the
governance core. They are deliberately free of any offensive-tool specifics:
a tool adapter maps its own arguments onto a ``ToolRequest`` and the core
decides, uniformly, whether that request may proceed.
"""

from __future__ import annotations

import enum
from datetime import UTC, datetime

from pydantic import BaseModel, Field, field_validator


class AuthorityTier(enum.IntEnum):
    """Four-tier authority hierarchy, highest number == highest privilege.

    The ordering is what enforcement compares against; see ``authority.py``.
    Directive precedence is System > Developer > User > Embedded, meaning a
    lower tier can never widen what a higher tier has constrained.
    """

    EMBEDDED = 0  # instructions arriving inside tool output / fetched content
    USER = 1  # the human operator driving the engagement
    DEVELOPER = 2  # the deploying engineer's configured policy
    SYSTEM = 3  # the framework's own non-negotiable guardrails


class Decision(enum.StrEnum):
    """Outcome of a governance evaluation."""

    ALLOW = "allow"
    DENY = "deny"
    NEEDS_APPROVAL = "needs_approval"


class Principal(BaseModel):
    """The identity and authority context a request is evaluated against."""

    id: str = Field(..., min_length=1, description="Stable caller identifier.")
    tier: AuthorityTier = Field(
        default=AuthorityTier.USER,
        description="Authority tier this principal is acting under.",
    )
    engagement_id: str = Field(
        ..., min_length=1, description="The authorized engagement this call belongs to."
    )


class ToolRequest(BaseModel):
    """A normalized request to run a governed tool against a target."""

    tool: str = Field(..., min_length=1, description="Registered tool name.")
    target: str = Field(
        ...,
        min_length=1,
        description="Host, CIDR, URL, or identifier the tool would act on.",
    )
    action: str = Field(
        default="default",
        description="Sub-action within the tool (e.g. a scan profile name).",
    )
    arguments: dict[str, str] = Field(
        default_factory=dict, description="Opaque, tool-specific string arguments."
    )
    requested_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC)
    )

    @field_validator("target")
    @classmethod
    def _strip_target(cls, value: str) -> str:
        return value.strip()


class GovernanceResult(BaseModel):
    """The uniform verdict returned by the governance core."""

    decision: Decision
    reason: str = Field(..., description="Human-readable basis for the decision.")
    audit_seq: int | None = Field(
        default=None, description="Sequence number of the audit entry, if written."
    )
    approval_challenge: str | None = Field(
        default=None,
        description="When NEEDS_APPROVAL, the payload an approver must sign.",
    )
