# needs-engine (from attack suite X1 — attacks on trust)

Fix proposal for the RampartEngine owner (B1). Scenario X1.16. Not drivable from the behaviour
harness (no real updater is touched during tests); recorded as a design gap.

## Finding E-X1-1 (High): signature / hash-feed poisoning can whitelist malware

**Where.** The MalwareBazaar recent-SHA-256 hash-feed updater and the SQLite hash DB
(known-bad + **allowlist**) in RampartEngine.

**Problem.** A malicious or MITM'd feed is trusted on the strength of TLS alone. Two trust
bypasses follow: (a) a poisoned feed can *add allowlist / known-good hashes*, whitelisting a
specific sample so no other engine flags it; (b) a feed can be truncated or replayed to roll the
known-bad set back. `AllowEntry` carries only a free-text `note` — a feed-sourced allow is
indistinguishable from a user decision, so there is no provenance to audit or revoke.

**Proposed fix.**
1. Feeds must be *authenticated*, not just TLS-fetched: ship a pinned publisher public key and
   verify a detached signature (or a signed manifest with a content hash) before any entry is
   imported. Reject on signature/length/encoding failure (the downloader already validates
   status+content per ARCHITECTURE; extend it to signature).
2. **Feeds may only add known-BAD entries. Allowlist / known-good entries must never come from a
   remote feed** — only from a local user decision or the signed baseline. Tag every allowlist
   row with its source (`user` | `baseline`) and refuse `feed`.
3. Monotonic version / timestamp with rollback protection; sanity caps on entry count and per-run
   delta so a feed cannot wholesale replace the DB.
4. Keep a provenance column on allowlist/known-good rows for audit and one-click revoke.
