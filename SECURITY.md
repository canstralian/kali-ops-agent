# Security & Authorized-Use Policy

`kali-ops-agent` is infrastructure for **authorized** security work. It is a
governance control plane — it ships authorization, scope enforcement, and audit,
not offensive payloads. Using it responsibly is a precondition of using it at all.

## Authorized use only

Every action driven through this framework must fall under an explicit,
documented authorization: a signed penetration-testing engagement, a bug-bounty
program's stated scope, a CTF you are entered in, a lab you own, or equivalent
written permission. Operating against systems you are not authorized to test is
unlawful in most jurisdictions and is not a supported use of this project.

The controls exist to make that boundary enforceable, not decorative:

- **Engagement scope** is an allowlist with a hard block. Out-of-scope targets
  are denied by construction; there is no "scan everything" mode and no runtime
  switch to disable scope.
- **Authority hierarchy** (System > Developer > User > Embedded) ensures that
  instructions arriving inside tool output or fetched content can never widen
  scope, grant approvals, or raise privilege.
- **Approval tokens** gate high-impact actions on an out-of-band human signature.
- **The audit log** is append-only and hash-chained, so every decision —
  allow or deny — is provable after the fact.

Do not weaken these controls to "make things easier." If a control is in your
way, the correct move is to widen the *authorization* (add a scope entry, raise
your tier deliberately), not to bypass the check.

## Reporting a vulnerability

If you find a security issue in this framework, please report it privately via
the repository's security advisories rather than opening a public issue. Include
reproduction steps and the affected version.

## Secrets

The approval secret is read only from the `KALI_OPS_APPROVAL_SECRET` environment
variable and must never be committed. Engagement scope files and audit logs are
git-ignored by default.
