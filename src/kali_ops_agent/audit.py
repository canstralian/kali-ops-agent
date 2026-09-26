"""Tamper-evident audit log built on a hash chain.

Every governed decision — allow, deny, or needs-approval — is appended as an
entry whose hash includes the previous entry's hash. Any retroactive edit,
deletion, or reordering breaks the chain and is detected by ``verify``. The log
is append-only from the caller's perspective; there is no update or delete API.

This is the accountability backbone: an authorized engagement can prove, after
the fact, exactly what was requested, what was decided, and why.
"""

from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from .errors import AuditError

GENESIS_HASH = "0" * 64


@dataclass(frozen=True)
class AuditEntry:
    seq: int
    timestamp: str
    principal_id: str
    engagement_id: str
    tool: str
    target: str
    action: str
    decision: str
    reason: str
    prev_hash: str
    entry_hash: str = field(default="")

    def _digest_input(self) -> bytes:
        body = {k: v for k, v in asdict(self).items() if k != "entry_hash"}
        return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def compute_hash(self) -> str:
        return hashlib.sha256(self._digest_input()).hexdigest()


class AuditLog:
    """Append-only, hash-chained audit log with optional JSONL persistence."""

    def __init__(self, path: str | Path | None = None) -> None:
        self._entries: list[AuditEntry] = []
        self._lock = threading.Lock()
        self._path = Path(path) if path else None
        if self._path and self._path.exists():
            self._load()

    def _load(self) -> None:
        assert self._path is not None
        for line in self._path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            data = json.loads(line)
            self._entries.append(AuditEntry(**data))
        self.verify()

    def _last_hash(self) -> str:
        return self._entries[-1].entry_hash if self._entries else GENESIS_HASH

    def append(
        self,
        *,
        principal_id: str,
        engagement_id: str,
        tool: str,
        target: str,
        action: str,
        decision: str,
        reason: str,
    ) -> AuditEntry:
        """Append one decision to the chain and return the sealed entry."""
        with self._lock:
            seq = len(self._entries)
            draft = AuditEntry(
                seq=seq,
                timestamp=datetime.now(UTC).isoformat(),
                principal_id=principal_id,
                engagement_id=engagement_id,
                tool=tool,
                target=target,
                action=action,
                decision=decision,
                reason=reason,
                prev_hash=self._last_hash(),
            )
            sealed = AuditEntry(**{**asdict(draft), "entry_hash": draft.compute_hash()})
            self._entries.append(sealed)
            if self._path:
                self._persist(sealed)
            return sealed

    def _persist(self, entry: AuditEntry) -> None:
        assert self._path is not None
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with self._path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(asdict(entry), separators=(",", ":")) + "\n")

    def verify(self) -> None:
        """Re-derive the chain and fail closed on the first inconsistency.

        Raises:
            AuditError: if any entry's hash or back-link does not reconcile.
        """
        prev = GENESIS_HASH
        for index, entry in enumerate(self._entries):
            if entry.seq != index:
                raise AuditError(f"audit entry out of order at index {index}")
            if entry.prev_hash != prev:
                raise AuditError(f"audit chain broken at seq {entry.seq}")
            if entry.compute_hash() != entry.entry_hash:
                raise AuditError(f"audit entry tampered at seq {entry.seq}")
            prev = entry.entry_hash

    @property
    def entries(self) -> list[AuditEntry]:
        return list(self._entries)
