# json-chamber-mcp

[![Audited checks](https://github.com/ceedot-rock/json-chamber-mcp/actions/workflows/audited-checks.yml/badge.svg)](https://github.com/ceedot-rock/json-chamber-mcp/actions/workflows/audited-checks.yml)
[![License: BUSL-1.1](https://img.shields.io/badge/license-BUSL--1.1-blue.svg)](LICENSE)

**Chamber MCP** — seal / open JSON. Slid Phi Labs.

Cloak (seal new JSON) needs a live license. Open of an already-sealed blob is both keys, no extra payment. Ciphertext does not expire.

## Install / run

```bash
npx -y json-chamber-mcp
```

```json
{
  "mcpServers": {
    "json-chamber": {
      "command": "npx",
      "args": ["-y", "json-chamber-mcp"],
      "env": {
        "CHAMBER_MASTER_SECRET": "your-high-entropy-secret"
      }
    }
  }
}
```

## Discovery

| Surface | URL |
|---------|-----|
| Official registry id | `io.github.ceedot-rock/json-chamber-mcp` |
| Lab well-known | https://www.slidphilabs.com/.well-known/mcp.json |
| Lab llms.txt | https://www.slidphilabs.com/llms.txt |
| npm | `json-chamber-mcp` 1.2.0 |
| Server schema | [`server.json`](server.json) |
| Product | https://www.slidphilabs.com/chamber |

Hosted lab MCP (PCC + catalog): `POST https://www.slidphilabs.com/mcp` · Smithery: https://smithery.ai/servers/slidphi/lab

## Pricing

| SKU | What | Price |
|-----|------|-------|
| Chamber try | cloak new JSON | 24 hours free |
| Chamber month | cloak license | $9 |
| Chamber year | cloak license | $99 |
| Open | already-sealed blob | keys only |

Prices live on https://www.slidphilabs.com/chamber

## License recovery

Cloak needs a live license: either the 24-hour trial from first run or a
signed purchased license (`license.json` with `purchased: true`, HMAC-signed
under your `CHAMBER_MASTER_SECRET`). A purchase never comes from an API key
or key value — no key substring unlocks cloak.

`~/.chamber` is created mode `0700` and `license.json` / `KILLED` are mode
`0600`, so other local processes cannot kill or corrupt your license. A
master secret must be configured (`CHAMBER_MASTER_SECRET`, or
`JSON_CHAMBER_MASTER` / `TRU8_MASTER_SECRET`); without one the gate fails
closed — cloak stays off and no license file is written. There is no
default or demo secret.

If cloak reports dead (`KILLED` marker present, e.g. the trial expired or
a license signature mismatch was detected):

1. **Purchase revives automatically.** Installing a valid signed purchased
   `license.json` clears the `KILLED` marker on the next check — no manual
   step needed.
2. **Manual recovery.** Delete the marker (and, to restart a fresh 24-hour
   trial, the license file too):
   ```bash
   rm ~/.chamber/KILLED ~/.chamber/license.json
   ```
   The next `chamber_status` / `chamber_cloak` starts a new trial. A
   tamper kill (signature mismatch) stays in force for trial licenses
   until a purchase lands or the marker is deleted by hand — replacing the
   license file alone does not clear it.

## Tools

| Tool | Purpose |
|------|--------|
| `chamber_status` | cloak try remaining / dead / purchased |
| `chamber_info` | pointer to live prices |
| `chamber_cloak` | seal JSON / text (licensed) |
| `chamber_open` | open sealed blob (keys only) |
| `chamber_hop_gate` | admit/reject hop (gate only) |
| `chamber_hop_reject_log` | live sanitized reject log |
| `chamber_lease_export` | export as ciphertext + key lease (#25) |
| `chamber_lease_decrypt` | decrypt via revocation service (#25) |
| `chamber_lease_revoke` | revoke a lease — all copies go dark (#25) |
| `chamber_lease_renew` / `chamber_lease_status` | lease renewal / status (#25) |
| `chamber_transparency_seal` | seal + append content hash to log (#31) |
| `chamber_transparency_open` | verified read, refused unless proven (#31) |
| `chamber_transparency_status` / `chamber_transparency_verify` | log head / proof check (#31) |

## Batch 4 features (2026-11-18)

- **#33 Erasure receipts** — library API (`src/erasure.ts`): `CopyRegistry` +
  `InMemoryCopyLocation`. Deleting a record returns a signed receipt
  enumerating every registered copy location (primary, fragment, backup,
  snapshot, cache, index, derived) with a probe-verified removal attestation
  from each, or a signed retention-lock statement with the exact expiry date.
  A location that does not answer, or whose removal an independent probe
  contradicts, is an open item and the receipt is marked incomplete. Chamber
  MCP holds no copy store of its own, so there is deliberately no MCP tool
  for this — the host application registers its real locations.
- **#25 Key-lease revocation** — `src/key-lease.ts` + MCP tools
  `chamber_lease_*`. Exports leave as ciphertext + a short-lived lease; the
  recipient never holds the key (the DEK is wrapped under a key that lives
  only in the revocation service). Revocation is one act
  (`chamber_lease_revoke`); every copy goes dark at lease expiry. Leases are
  in-memory: a server restart drops all leases, which fails closed.
- **#31 Transparency-log-verified reads** — `src/transparency-log.ts` +
  MCP tools `chamber_transparency_*`. OPTIONAL mode, default OFF: plain
  `chamber_cloak` / `chamber_open` never consult the log.
  `chamber_transparency_seal` appends the SHA-256 content hash to an
  append-only Merkle log (Ed25519-signed tree head) and returns a signed
  inclusion promise; `chamber_transparency_open` recomputes the hash and
  requires an inclusion proof against the signed tree head — absent hash or
  forked log = read refused. Measured added read latency ≈ 1–4 ms
  (Ed25519 sign+verify), flat in log size. Log + keypair persist under
  `~/.chamber/transparency-log*.json`.


## Hop-gate (ScanChunk / Rider SoT)

Admission layer in front of seal/open. **Seal/open APIs are unchanged.** No SettleHop / x402.

Wire is **exact text** (Agent-Rider `agent-rider-c` / PR #22), not JSON:

```
CUNI ScanChunk
url=https://example.com/
etag="abc"
hash=sha256:…
agent_id=agt_1
```

Fields (allowlist): `url` · `etag` · `hash` · `agent_id`. Gate **result wire** is a single exact-text code string (not a JSON body).

| Code | Meaning |
|------|---------|
| `admit` | hop allowed |
| `reject.schema` | Chamber-local only (Rider does not emit) |
| `reject.extra` | unknown keys or wrong kind — fail-closed; do not bind; never rehydrate |
| `reject.hash` | empty / invalid hash |
| `reject.replay` | **hash** already seen |
| `reject.agent` | agent allowlist fail |
| `reject.empty` | empty / missing required fields (`url`, `hash`, `agent_id`) |

Live `reject.log` is TSV `ISO\tcode\tpreview` (mirrors `agent-rider-c/reject.log`); preview truncates ~120 and flattens newlines. Extra-key **values** never rehydrate as next machine input.

**PCC ≠ payment** — PCC is the compression/storefront face; hop-gate codes are admission control, not billing.

MCP tools: `chamber_hop_gate`, `chamber_hop_reject_log`.

## Related

- Python SDK: https://github.com/ceedot-rock/json-chamber-sdk
- Product: https://www.slidphilabs.com/chamber
- Contact: corey@slidphilabs.com
