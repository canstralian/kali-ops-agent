import dataclasses

import pytest

from kali_ops_agent.audit import AuditLog
from kali_ops_agent.errors import AuditError


def _append(log, decision="allow"):
    return log.append(
        principal_id="op-1",
        engagement_id="eng-1",
        tool="recon-stub",
        target="app.example.com",
        action="default",
        decision=decision,
        reason="test",
    )


def test_chain_verifies():
    log = AuditLog()
    _append(log)
    _append(log, decision="deny")
    log.verify()  # no raise
    assert [e.seq for e in log.entries] == [0, 1]


def test_tamper_is_detected():
    log = AuditLog()
    _append(log)
    _append(log)
    # Mutate a sealed entry in place to simulate tampering.
    log._entries[0] = dataclasses.replace(log._entries[0], reason="rewritten")
    with pytest.raises(AuditError):
        log.verify()


def test_persistence_round_trips(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    _append(log)
    _append(log, decision="deny")
    reloaded = AuditLog(path)  # _load calls verify()
    assert len(reloaded.entries) == 2
    assert reloaded.entries[1].decision == "deny"


def test_reordered_persisted_log_is_detected(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    _append(log)
    _append(log)
    lines = path.read_text().splitlines()
    path.write_text("\n".join(reversed(lines)) + "\n")
    with pytest.raises(AuditError):
        AuditLog(path)
