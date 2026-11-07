# needs-signing (from attack suite X1 — attacks on trust)

Fix proposals for the RampartSigning owner (B3). Scenarios X1.1 and X1.17.

## Finding S-X1-1 (Medium): "notarized" is a trust input, not a trust proof — stolen Developer ID

**Where.** `SigningInspector` status mapping and the `TrustClass` multipliers consumed by the
behaviour scorer (`notarized` ×0.3, `developerID` ×0.8).

**Observation (X1.1).** A payload signed with a *stolen but validly notarized* Developer ID cert
reports as `notarized`, getting the 0.3 trust discount. Behaviour still CAUGHT the stealer because
the alwaysActive credential rules (R34/R36/R38) survive the discount — good — but the margin is
thin, and a lone weak signal under notarized trust is suppressed (X1.2, by design). Notarization
proves Apple scanned the binary once; it does **not** prove the signer is who they claim or that
the cert is not stolen/revoked.

**Proposed fix.**
1. Check revocation live where possible (OCSP / `SecTrustEvaluateWithError` with revocation
   required) and treat a revoked cert as `.revoked` → `TrustClass.invalid` (×1.5), not notarized.
2. Feed the *Team ID* into behaviour as a first-class fact so a first-seen Team ID doing
   credential access does not get the full notarized discount (new-signer prior).
3. Surface "signed by <TeamID>, notarized — but new to this Mac" in the "Why was this flagged?"
   panel so the discount is visible, not silent.

## Finding S-X1-2 (High): poisoned RamPart auto-update must verify identity, not just a signature

**Where.** Update path (shared with RampartGuard `RamPartIdentity.isValidBundle` /
`trustedTeamIDs`, see redteam.md) and the packaging/update verification in signing.

**Observation (X1.17).** A poisoned update signed with a *different* Team ID must be rejected even
though it is "validly signed". Guard already holds bundle changes 30s and checks
`isValidBundle` + `trustedTeamIDs`; signing should (a) pin the expected update Team ID / cdhash of
the daemon + CLI, (b) require the update's embedded version be monotonic (no rollback), and
(c) verify the downloaded update's notarization ticket offline against the pinned Team ID before
swapping any bundle. Wire the pinned identity so Guard and the updater share one source of truth.
