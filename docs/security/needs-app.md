# needs-app (owner: B10)

Appended by attack pass X3 (2026-11-07). See docs/security/attacks-X3.md.

## X3-5 (Low) — UI copy for deepfake support calls & "can't be disabled by a website"
Scenarios S8/S12 are social: a voice-cloned "support" call or a fake in-browser RamPart alert. RamPart
sees only the consequence (remote-tool launch, scareware page), not the call. Add calm, specific copy:
- On a remote-access critical detection (S12): "You may be on a call with someone pretending to be
  support. Real Apple/RamPart support never asks you to install AnyDesk/TeamViewer or read codes aloud.
  Hang up and revoke access." with a one-tap "Revoke remote access" (already wired to
  `setRemoteLockdown`/`revokeRemoteTool`).
- On the protection screen: "RamPart can't be turned off by a website or a phone call — changing
  protection needs your admin password on this Mac." (reflects the IPC auth in redteam.md).
No new detection logic; copy + wiring to existing Guard commands.
