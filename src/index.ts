#!/usr/bin/env node
/**
 * json-chamber-mcp — Chamber MCP Server
 * Cloak needs a live license (24h try, then $9/mo · $99/yr).
 * Open is both shares (blob k_words + caller-held second share), no license, no clock.
 * Ciphertext does not expire. v1 blobs are rejected — re-seal under v2.
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { createPrivateKey, createPublicKey, type KeyObject } from "node:crypto";
import {
  existsSync,
  mkdirSync,
  readFileSync,
  writeFileSync,
} from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { LicenseManager, PRICE_USD, PURCHASE_URL } from "./license.js";
import {
  chamberSeal,
  chamberOpen,
  benefitCheck,
  type SealedBlob,
} from "./chamber.js";
import {
  evaluateHopGate,
  formatHopGateCode,
  listRejectLogTsv,
  loadPersistedRejectLog,
  type HopGateOptions,
} from "./hop-gate.js";
import {
  LeaseService,
  decryptLeasedBundle,
  exportLeasedBundle,
  type LeasedBundle,
} from "./key-lease.js";
import {
  TransparencyLog,
  openWithTransparency,
  sealWithTransparency,
} from "./transparency-log.js";

const licenseMgr = new LicenseManager();

/**
 * Batch 4, #25: process-lifetime revocation service. Leases live in memory
 * only — a server restart drops every lease, which fails CLOSED (all
 * bundles go dark), never open.
 */
const leaseService = new LeaseService();

/**
 * Batch 4, #31: file-backed transparency log. Leaves persist to
 * ~/.chamber/transparency-log.json and the Ed25519 keypair to
 * ~/.chamber/transparency-log-key.json so the log survives restarts.
 * Load never throws — a missing/corrupt file starts an empty log.
 */
const TLOG_DIR = join(homedir(), ".chamber");
const TLOG_FILE = join(TLOG_DIR, "transparency-log.json");
const TLOG_KEY_FILE = join(TLOG_DIR, "transparency-log-key.json");
const transparencyLog = loadTransparencyLog();

function loadTransparencyLog(): TransparencyLog {
  let keypair: { privateKey: KeyObject; publicKey: KeyObject } | undefined;
  try {
    if (existsSync(TLOG_KEY_FILE)) {
      const saved = JSON.parse(readFileSync(TLOG_KEY_FILE, "utf8")) as {
        privateKey: import("node:crypto").JsonWebKey;
        publicKey: import("node:crypto").JsonWebKey;
      };
      keypair = {
        privateKey: createPrivateKey({ key: saved.privateKey, format: "jwk" }),
        publicKey: createPublicKey({ key: saved.publicKey, format: "jwk" }),
      };
    }
  } catch {
    keypair = undefined; // corrupt key file: fresh keypair, fresh log identity
  }
  const log = new TransparencyLog(keypair);
  try {
    if (!existsSync(TLOG_KEY_FILE)) {
      mkdirSync(TLOG_DIR, { recursive: true });
      writeFileSync(
        TLOG_KEY_FILE,
        JSON.stringify(
          {
            privateKey: log.privateKeyJwk,
            publicKey: log.publicKeyJwk,
          },
          null,
          2
        )
      );
    }
  } catch {
    // Persistence is best-effort; the in-memory log still works.
  }
  try {
    if (existsSync(TLOG_FILE)) {
      const saved = JSON.parse(readFileSync(TLOG_FILE, "utf8")) as string[];
      if (Array.isArray(saved)) log.restoreLeaves(saved);
    }
  } catch {
    // Corrupt leaves file: start empty rather than serve a forked log.
  }
  return log;
}

function persistTransparencyLog(): void {
  try {
    mkdirSync(TLOG_DIR, { recursive: true });
    writeFileSync(TLOG_FILE, JSON.stringify(transparencyLog.serializeLeaves()));
  } catch {
    // Best-effort; the in-memory log is authoritative for this process.
  }
}

const server = new Server(
  { name: "json-chamber-mcp", version: "2.0.0" },
  { capabilities: { tools: {} } }
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: "chamber_status",
      description: "License status: eval remaining hours, purchased, or dead.",
      inputSchema: { type: "object", properties: {} },
    },
    {
      name: "chamber_info",
      description: "Package info, cloak license ($9/mo · $99/yr), open is keys-only.",
      inputSchema: { type: "object", properties: {} },
    },
    {
      name: "chamber_cloak",
      description:
        "Seal JSON/text with φ-split + AES-256-GCM (v2). Requires live license. " +
        "Returns the sealed blob AND a second share out-of-band: the blob alone cannot be opened. " +
        "Store second_share separately with the second custodian.",
      inputSchema: {
        type: "object",
        properties: {
          data: { type: "string", description: "JSON string or plain text" },
          is_json: { type: "boolean", description: "Validate as JSON (default true)" },
        },
        required: ["data"],
      },
    },
    {
      name: "chamber_open",
      description:
        "Open a sealed chamber blob. Requires the blob AND the second share returned at cloak time. " +
        "Neither alone opens anything. Keys only — no license, no clock. v1 blobs are rejected.",
      inputSchema: {
        type: "object",
        properties: {
          sealed: { type: "object", description: "Sealed blob from chamber_cloak (v2)" },
          second_share: { type: "string", description: "Second φ-share returned by chamber_cloak (24 words)" },
        },
        required: ["sealed", "second_share"],
      },
    },
    {
      name: "chamber_hop_gate",
      description:
        "Evaluate Chamber hop-gate (exact-text code). Gate only — does not seal/open/SettleHop. " +
        "Wire: CUNI ScanChunk + url/etag/hash/agent_id. Result: single code string. PCC ≠ payment.",
      inputSchema: {
        type: "object",
        properties: {
          hop: {
            type: "string",
            description:
              "Exact-text CUNI ScanChunk wire (not JSON). Fields: url etag hash agent_id. Extras → reject.extra.",
          },
          allowed_agents: {
            type: "array",
            items: { type: "string" },
            description: "Optional agent allowlist",
          },
        },
        required: ["hop"],
      },
    },
    {
      name: "chamber_hop_reject_log",
      description:
        "Durable hop-gate reject.log as TSV ISO\\tcode\\tpreview (Rider SoT). " +
        "Persisted to ~/.chamber/reject.log — survives a server restart. Extra values never rehydrate.",
      inputSchema: {
        type: "object",
        properties: {
          limit: { type: "number", description: "Max recent entries (optional)" },
        },
      },
    },
    {
      name: "benefit_check",
      description: "Entropy + bias gate for $1900 tier. Always available. No TRU8.",
      inputSchema: {
        type: "object",
        properties: {
          data: { type: "string", description: "UTF-8 text or base64 binary" },
          encoding: { type: "string", enum: ["utf8", "base64"] },
        },
        required: ["data"],
      },
    },
    {
      name: "chamber_lease_export",
      description:
        "Batch 4 #25 — export data as ciphertext + short-lived key lease. The recipient NEVER holds the key: decryption goes through this server's revocation service while the lease is live. Revoke once and all copies go dark at expiry. Requires live license (like chamber_cloak).",
      inputSchema: {
        type: "object",
        properties: {
          data: { type: "string", description: "JSON string or plain text" },
          is_json: { type: "boolean", description: "Validate as JSON (default true)" },
          ttl_ms: { type: "number", description: "Lease lifetime in milliseconds (default 3600000 = 1h)" },
        },
        required: ["data"],
      },
    },
    {
      name: "chamber_lease_decrypt",
      description:
        "Batch 4 #25 — decrypt a leased bundle. Goes through the revocation service every time: a revoked or expired lease is refused, no plaintext. Keys only — no license.",
      inputSchema: {
        type: "object",
        properties: {
          bundle: { type: "object", description: "Leased bundle from chamber_lease_export" },
        },
        required: ["bundle"],
      },
    },
    {
      name: "chamber_lease_revoke",
      description:
        "Batch 4 #25 — THE revocation act. One call revokes the lease; every copy of every bundle on it goes dark (decryption refused immediately, and at expiry at the latest).",
      inputSchema: {
        type: "object",
        properties: {
          lease_id: { type: "string", description: "Lease id from chamber_lease_export" },
        },
        required: ["lease_id"],
      },
    },
    {
      name: "chamber_lease_renew",
      description:
        "Batch 4 #25 — renew a live, unrevoked lease for a further ttl_ms from now. Renewal of a revoked or expired lease is refused.",
      inputSchema: {
        type: "object",
        properties: {
          lease_id: { type: "string" },
          ttl_ms: { type: "number", description: "Additional lifetime in milliseconds" },
        },
        required: ["lease_id", "ttl_ms"],
      },
    },
    {
      name: "chamber_lease_status",
      description: "Batch 4 #25 — lease record: live / revoked / expired, with expiry time.",
      inputSchema: {
        type: "object",
        properties: {
          lease_id: { type: "string" },
        },
        required: ["lease_id"],
      },
    },
    {
      name: "chamber_transparency_seal",
      description:
        "Batch 4 #31 — seal + append the content hash to the transparency log (Merkle tree, Ed25519-signed tree head). Returns the sealed blob, second share, content hash and signed inclusion promise. Requires live license (like chamber_cloak).",
      inputSchema: {
        type: "object",
        properties: {
          data: { type: "string", description: "JSON string or plain text" },
          is_json: { type: "boolean", description: "Validate as JSON (default true)" },
        },
        required: ["data"],
      },
    },
    {
      name: "chamber_transparency_open",
      description:
        "Batch 4 #31 — verified read: opens the blob, recomputes the content hash, and requires an inclusion proof against the log's signed tree head. Absent hash or forked log = read REFUSED, never served. Keys only — no license.",
      inputSchema: {
        type: "object",
        properties: {
          sealed: { type: "object", description: "Sealed blob from chamber_transparency_seal (v2)" },
          second_share: { type: "string", description: "Second φ-share returned at seal time (24 words)" },
        },
        required: ["sealed", "second_share"],
      },
    },
    {
      name: "chamber_transparency_status",
      description: "Batch 4 #31 — transparency log status: leaf count, current signed tree head, public key (JWK) for independent verification.",
      inputSchema: { type: "object", properties: {} },
    },
    {
      name: "chamber_transparency_verify",
      description: "Batch 4 #31 — verify the inclusion proof for a leaf index against the log's signed tree head. Returns true only when signature AND Merkle path both verify.",
      inputSchema: {
        type: "object",
        properties: {
          leaf_index: { type: "number", description: "Leaf index (0-based)" },
        },
        required: ["leaf_index"],
      },
    },
  ],
}));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;
  const a = (args ?? {}) as Record<string, unknown>;
  try {
    if (name === "chamber_status") {
      return {
        content: [{ type: "text", text: JSON.stringify(licenseMgr.check(), null, 2) }],
      };
    }
    if (name === "chamber_info") {
      const st = licenseMgr.check();
      return {
        content: [{
          type: "text",
          text: JSON.stringify({
            package: "json-chamber-mcp",
            version: "2.0.0",
            product: "json-chamber",
            lab: "Slid Phi Labs",
            pricing: {
              cloak_month: "$9 / month",
              cloak_year: "$99 / year",
              open: "keys only — no extra payment",
            },
            trial: "24 hours of cloak from first run. Open stays keys-only after that.",
            unlock: `Pay a cloak license at ${PURCHASE_URL} — a signed license unlocks cloak; open stays keys-only.`,
            purchase_url: PURCHASE_URL,
            python_sdk: "https://github.com/ceedot-rock/json-chamber-sdk",
            license_status: st,
          }, null, 2),
        }],
      };
    }
    if (name === "benefit_check") {
      const dataStr = String(a.data ?? "");
      const enc = a.encoding === "base64" ? "base64" : "utf8";
      const buf = enc === "base64" ? Buffer.from(dataStr, "base64") : Buffer.from(dataStr, "utf8");
      return {
        content: [{ type: "text", text: JSON.stringify(benefitCheck(buf), null, 2) }],
      };
    }
    if (name === "chamber_cloak") {
      licenseMgr.requireAlive();
      const dataStr = String(a.data ?? "");
      if (a.is_json !== false) {
        try { JSON.parse(dataStr); } catch {
          throw new Error("data is not valid JSON (set is_json=false for plain text)");
        }
      }
      const { sealed, secondShare } = chamberSeal(Buffer.from(dataStr, "utf8"));
      return {
        content: [{
          type: "text",
          text: JSON.stringify({
            sealed,
            second_share: secondShare,
            custody:
              "two-share — the sealed blob alone cannot be opened. Store second_share separately with the second custodian; anyone holding both shares can open.",
          }, null, 2),
        }],
      };
    }
    if (name === "chamber_open") {
      const sealed = a.sealed as SealedBlob;
      const secondShare = a.second_share;
      if (!sealed || typeof sealed !== "object") throw new Error("sealed object required");
      if (typeof secondShare !== "string" || !secondShare.trim()) {
        throw new Error("second_share required — the blob alone cannot be opened (two-share custody)");
      }
      const opened = chamberOpen(sealed, secondShare);
      const text = opened.toString("utf8");
      let parsed: unknown = text;
      try { parsed = JSON.parse(text); } catch { /* plain */ }
      return {
        content: [{ type: "text", text: JSON.stringify({ ok: true, data: parsed }, null, 2) }],
      };
    }
    if (name === "chamber_hop_gate") {
      const hop = a.hop;
      const allowed = Array.isArray(a.allowed_agents)
        ? (a.allowed_agents as string[])
        : undefined;
      const gateOpts: HopGateOptions = allowed ? { allowedAgents: allowed } : {};
      const result = evaluateHopGate(hop, gateOpts);
      // Gate result wire: single exact-text code string (no JSON body)
      return {
        content: [{ type: "text", text: formatHopGateCode(result.code) }],
        ...(result.ok ? {} : { isError: true }),
      };
    }
    if (name === "chamber_hop_reject_log") {
      const limit =
        typeof a.limit === "number" ? a.limit : undefined;
      return {
        content: [{
          type: "text",
          text: listRejectLogTsv(limit),
        }],
      };
    }
    if (name === "chamber_lease_export") {
      licenseMgr.requireAlive();
      const dataStr = String(a.data ?? "");
      if (a.is_json !== false) {
        try { JSON.parse(dataStr); } catch {
          throw new Error("data is not valid JSON (set is_json=false for plain text)");
        }
      }
      const ttlMs =
        typeof a.ttl_ms === "number" && a.ttl_ms > 0 ? a.ttl_ms : 3600000;
      const bundle = exportLeasedBundle(
        Buffer.from(dataStr, "utf8"),
        leaseService,
        ttlMs
      );
      return {
        content: [{
          type: "text",
          text: JSON.stringify({
            bundle,
            custody:
              "key-lease — the recipient holds ciphertext + wrapped key only. Decryption goes through the revocation service while the lease is live; revoke the lease and all copies go dark.",
          }, null, 2),
        }],
      };
    }
    if (name === "chamber_lease_decrypt") {
      const bundle = a.bundle as LeasedBundle;
      if (!bundle || typeof bundle !== "object") throw new Error("bundle required");
      const opened = decryptLeasedBundle(bundle, leaseService);
      const text = opened.toString("utf8");
      let parsed: unknown = text;
      try { parsed = JSON.parse(text); } catch { /* plain */ }
      return {
        content: [{ type: "text", text: JSON.stringify({ ok: true, data: parsed }, null, 2) }],
      };
    }
    if (name === "chamber_lease_revoke") {
      const leaseId = String(a.lease_id ?? "");
      if (!leaseId) throw new Error("lease_id required");
      const rec = leaseService.revoke(leaseId);
      return {
        content: [{
          type: "text",
          text: JSON.stringify({
            ok: true,
            lease: rec,
            note: "Revoked. Every copy of every bundle on this lease is now dark.",
          }, null, 2),
        }],
      };
    }
    if (name === "chamber_lease_renew") {
      const leaseId = String(a.lease_id ?? "");
      const ttlMs = Number(a.ttl_ms);
      if (!leaseId) throw new Error("lease_id required");
      const rec = leaseService.renew(leaseId, ttlMs);
      return {
        content: [{ type: "text", text: JSON.stringify({ ok: true, lease: rec }, null, 2) }],
      };
    }
    if (name === "chamber_lease_status") {
      const leaseId = String(a.lease_id ?? "");
      if (!leaseId) throw new Error("lease_id required");
      const rec = leaseService.getLease(leaseId);
      if (!rec) throw new Error(`unknown lease: ${leaseId}`);
      return {
        content: [{
          type: "text",
          text: JSON.stringify({
            ...rec,
            live: leaseService.isLive(leaseId),
            expires_at: new Date(rec.expiresAt).toISOString(),
          }, null, 2),
        }],
      };
    }
    if (name === "chamber_transparency_seal") {
      licenseMgr.requireAlive();
      const dataStr = String(a.data ?? "");
      if (a.is_json !== false) {
        try { JSON.parse(dataStr); } catch {
          throw new Error("data is not valid JSON (set is_json=false for plain text)");
        }
      }
      const res = sealWithTransparency(
        Buffer.from(dataStr, "utf8"),
        transparencyLog
      );
      persistTransparencyLog();
      return {
        content: [{
          type: "text",
          text: JSON.stringify({
            sealed: res.sealed,
            second_share: res.secondShare,
            content_hash: res.contentHash,
            inclusion_promise: res.inclusionPromise,
            custody:
              "two-share — the sealed blob alone cannot be opened. Store second_share separately with the second custodian.",
          }, null, 2),
        }],
      };
    }
    if (name === "chamber_transparency_open") {
      const sealed = a.sealed as SealedBlob;
      const secondShare = a.second_share;
      if (!sealed || typeof sealed !== "object") throw new Error("sealed object required");
      if (typeof secondShare !== "string" || !secondShare.trim()) {
        throw new Error("second_share required — the blob alone cannot be opened (two-share custody)");
      }
      const opened = openWithTransparency(sealed, secondShare, transparencyLog);
      const text = opened.toString("utf8");
      let parsed: unknown = text;
      try { parsed = JSON.parse(text); } catch { /* plain */ }
      return {
        content: [{ type: "text", text: JSON.stringify({ ok: true, verified: true, data: parsed }, null, 2) }],
      };
    }
    if (name === "chamber_transparency_status") {
      const head = transparencyLog.currentTreeHead();
      return {
        content: [{
          type: "text",
          text: JSON.stringify({
            leaves: transparencyLog.size,
            tree_head: head,
            tree_head_sig: transparencyLog.signTreeHead(head),
            public_key_jwk: transparencyLog.publicKeyJwk,
            mode: "opt-in — plain chamber_cloak/chamber_open never consult the log",
          }, null, 2),
        }],
      };
    }
    if (name === "chamber_transparency_verify") {
      const leafIndex = Number(a.leaf_index);
      if (!Number.isInteger(leafIndex) || leafIndex < 0) {
        throw new Error("leaf_index required (0-based integer)");
      }
      const proof = transparencyLog.inclusionProof(leafIndex);
      const ok = transparencyLog.verifyInclusion(proof);
      return {
        content: [{ type: "text", text: JSON.stringify({ ok, proof }, null, 2) }],
      };
    }
    throw new Error(`Unknown tool: ${name}`);
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    return {
      content: [{ type: "text", text: JSON.stringify({ error: msg }) }],
      isError: true,
    };
  }
});

async function main() {
  // Durable audit log: entries written by earlier processes are visible to
  // chamber_hop_reject_log from this process onward. Never throws.
  loadPersistedRejectLog();
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
