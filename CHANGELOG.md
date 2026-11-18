# Changelog — json-chamber-mcp

## Unreleased — Batch 4 (2026-11-18): erasure receipts, key leases, transparency log

- **#33 Erasure receipts** (`src/erasure.ts`, `src/signing.ts`): signed
  receipts enumerating every copy location with probe-verified removal
  attestations or signed retention-lock statements with exact expiry;
  no-answer / unverified locations are open items, receipt incomplete.
  Library API — no MCP tool (Chamber holds no copy store).
- **#25 Key-lease revocation** (`src/key-lease.ts`): leased exports,
  revocation service, one-act revoke; MCP tools `chamber_lease_*`.
- **#31 Transparency-log-verified reads** (`src/transparency-log.ts`):
  opt-in Merkle log with Ed25519-signed tree heads; verified reads refuse
  absent/forked content; default OFF; MCP tools `chamber_transparency_*`.
  Measured added read latency ≈ 1–4 ms, flat in log size.
- Tests: 38 → 55 passing (`src/batch4.test.ts`, 17 new).

## Unreleased — v2 custody + durable audit (KMS match)

Closes the two gaps where AWS KMS beat Chamber in the 2026-11-17
head-to-head (`~/workspace/your_files/chamber-vs-age-kms-2026-11-17.md`):
durable audit and split custody. Code, not claims — both are tested, and
the live MCP verification is in
`~/workspace/your_files/chamber-kms-match-2026-11-17.md`.

### BREAKING — format v2, two-share custody

- The session key is now **random per seal**. It is no longer derived from
  the master secret (`SHA-256(master ‖ "chamber-phi-v1")` is gone).
- `chamberSeal` returns `{ sealed, secondShare }`. The sealed blob (v2)
  carries only the FIRST share (`k_words`); the SECOND share (`r_words`
  equivalent) is returned **out of band** and is never embedded in the blob.
  Store it separately with the second custodian.
- `chamberOpen(sealed, secondShare)` requires BOTH shares. The blob alone
  cannot be opened; the master secret alone cannot open anything — there is
  no master input to open at all. The master secret remains the
  cloak-license identity only (see `license.ts`).
- **v1 blobs are REJECTED, never silently opened.** Opening a v1 blob
  (both shares embedded) throws `chamber v1 blob rejected — re-seal under
  v2`. Any blob sealed before this change must be re-sealed under v2;
  the v1 sealed receipt from the CuNi walkthrough can no longer be opened.
- AAD changed from `chamber-v1` to `chamber-v2`, binding ciphertext to the
  format version.
- MCP wire change: `chamber_cloak` returns `{ sealed, second_share,
  custody }`; `chamber_open` now requires `second_share` (string, 24
  words). Shares are validated strictly (word count + wordlist membership)
  before decryption; a wrong second share fails closed via GCM auth.

### Durable audit log

- The hop-gate reject log is now **append-only on disk** at
  `~/.chamber/reject.log` (TSV `ISO\tcode\tpreview`, same shape as the
  live log, extra values still withheld). Every reject writes immediately.
- `chamber_hop_reject_log` returns the persisted entries and **survives a
  server restart**: the server loads `~/.chamber/reject.log` at startup.
- `HopGateOptions.logFile` overrides the path; `logFile: null` is
  in-memory only (used by the test suite so unit-test rejects do not
  pollute the production audit log). A log-write failure never fails the
  gate (best-effort, swallowed).
- Known limit: the log file is append-only with no rotation yet. Rotate /
  cap it before it grows unbounded in long-lived deployments.

### Smaller blobs (side effect)

- Dropping `r_words` from the blob shrinks sealed size. Measured on the
  2026-11-17 corpus (see the verification report for the new table):
  the blob still carries base64 ciphertext + JSON framing, so it remains
  larger than age's flat +200 B — but the total stored material
  (blob + separately-held second share) is unchanged in bytes. The win is
  custody separation, not compression; do not claim otherwise.

### Tests

- New `src/chamber.test.ts`: φ-split round-trip, seal shape, both-shares
  open (byte-exact), blob-alone fails, wrong/garbage/short second share
  fails closed, master-derived key fails GCM under both AADs, tamper
  fails closed, v1 blob (synthetic + the real saved v1 receipt) rejected,
  v2 blob carrying `r_words` rejected, unknown version rejected.
- New durable-log tests in `src/hop-gate.test.ts`: immediate TSV write,
  simulated restart (reset → load restores), double-load dedup,
  `logFile: null` writes nothing, unwritable path never throws.
- `npm test` now runs both suites (17 hop-gate + new chamber tests).

### Version recommendation (NOT applied)

This is a breaking change to the blob format and the MCP wire. **Recommend
bumping to 2.0.0** (semver major). The version number was deliberately left
at 1.2.1 in this change — the bump is a release decision, not a code
decision. Note: `src/index.ts` still reports server version `1.2.0` in its
`Server` constructor, a pre-existing inconsistency with `package.json`
1.2.1; align it when the bump lands.

### Removed

- `deriveSessionKey` (master-derived session keys) and the `getMaster`
  helper in `src/index.ts` — no longer used by seal/open. `license.ts`
  still reads the master secret from env for license HMAC; that is
  unchanged and the trial-license hazard is unchanged: **never run the
  server under any master secret other than the one that created the
  license file**, or the license is hard-killed.
