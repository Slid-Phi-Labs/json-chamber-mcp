/**
 * Hop-gate tests: ScanChunk Rider SoT (Agent-Rider #22 / agent-rider-c).
 * Wire is exact text. PCC ≠ payment. No SettleHop / x402.
 */

import { describe, it, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  evaluateHopGate,
  appendRejectLog,
  loadPersistedRejectLog,
  listRejectLog,
  listRejectLogTsv,
  formatRejectLogLine,
  resetHopGateState,
  sanitizeHopInput,
  nextMachineInput,
  formatScanChunkText,
  formatHopGateCode,
  sanitizePreview,
  DEFAULT_REJECT_LOG_FILE,
  HOP_GATE_CODES,
  SCAN_CHUNK_HEADER,
  type HopGateOptions,
} from "./hop-gate.js";

const fixedNow = () => new Date("2026-09-17T04:00:00.000Z");

function opts(over: HopGateOptions = {}): HopGateOptions {
  // logFile: null keeps the suite hermetic — unit-test rejects must not
  // append to the production audit log (~/.chamber/reject.log).
  return { now: fixedNow, seenHashes: new Set(), logFile: null, ...over };
}

function chunk(
  fields: Record<string, string>,
  extraLines: string[] = []
): string {
  const base = formatScanChunkText(fields);
  if (!extraLines.length) return base;
  return base.replace(/\n$/, "\n") + extraLines.join("\n") + "\n";
}

beforeEach(() => {
  resetHopGateState();
});

describe("hop-gate codes", () => {
  it("exposes Rider chamber set + Chamber-local reject.schema", () => {
    assert.deepEqual([...HOP_GATE_CODES], [
      "admit",
      "reject.schema",
      "reject.extra",
      "reject.hash",
      "reject.replay",
      "reject.agent",
      "reject.empty",
    ]);
    for (const c of HOP_GATE_CODES) {
      assert.equal(formatHopGateCode(c), c);
    }
  });
});

describe("admit happy path", () => {
  it("admits well-formed exact-text ScanChunk", () => {
    const text = chunk({
      url: "https://example.com/",
      etag: '"abc"',
      hash: "sha256:dead",
      agent_id: "agt_1",
    });
    assert.ok(text.startsWith(SCAN_CHUNK_HEADER));
    const r = evaluateHopGate(text, opts({ allowedAgents: ["agt_1"] }));
    assert.equal(r.code, "admit");
    assert.equal(r.ok, true);
    assert.equal(r.at, "2026-09-17T04:00:00Z");
    assert.equal(formatHopGateCode(r.code), "admit");
    assert.equal(listRejectLog().length, 0);
  });
});

describe("reject.empty", () => {
  it("rejects null", () => {
    assert.equal(evaluateHopGate(null, opts()).code, "reject.empty");
  });

  it("rejects blank text", () => {
    assert.equal(evaluateHopGate("   \n", opts()).code, "reject.empty");
  });

  it("rejects missing required fields (url/hash/agent_id)", () => {
    const text = `${SCAN_CHUNK_HEADER}\netag="x"\n`;
    assert.equal(evaluateHopGate(text, opts()).code, "reject.empty");
  });

  it("rejects header with only etag (missing url hash agent_id)", () => {
    const text = chunk({ etag: '"only"' });
    assert.equal(evaluateHopGate(text, opts()).code, "reject.empty");
  });
});

describe("reject.schema (Chamber-local)", () => {
  it("rejects non-text array (Rider does not emit reject.schema)", () => {
    assert.equal(evaluateHopGate(["nope"], opts()).code, "reject.schema");
  });

  it("rejects non-string field on object path", () => {
    const r = evaluateHopGate(
      { url: "https://x/", hash: "h", agent_id: 1 as unknown as string },
      opts()
    );
    assert.equal(r.code, "reject.schema");
  });
});

describe("reject.extra", () => {
  it("wrong kind maps to reject.extra (Rider KIND→extra)", () => {
    const text = "CUNI SettleHop\nhop_id=x\njob_id=y\nkey_id=z\n";
    const r = evaluateHopGate(text, opts());
    assert.equal(r.code, "reject.extra");
  });

  it("malformed kv line → reject.extra", () => {
    const text = `${SCAN_CHUNK_HEADER}\nurl=https://x/\nhash=h\nagent_id=a\nnot-a-kv\n`;
    assert.equal(evaluateHopGate(text, opts()).code, "reject.extra");
  });

  it("fail-closed on extra keys; values never rehydrate", () => {
    const text = chunk(
      {
        url: "https://evil.example/",
        etag: '"x"',
        hash: "sha256:evil",
        agent_id: "agt_sitescan",
      },
      ["smuggle=evil-blob-should-not-rehydrate"]
    );
    const r = evaluateHopGate(text, opts());
    assert.equal(r.code, "reject.extra");
    assert.equal(r.ok, false);

    const log = listRejectLog();
    assert.equal(log.length, 1);
    assert.equal(log[0].code, "reject.extra");
    // preview mirrors reject.log: wire with newlines→spaces; may include key names
    assert.ok(log[0].preview.includes("smuggle"));
    assert.equal(log[0].preview.includes("evil-blob-should-not-rehydrate"), false);

    const next = nextMachineInput(text);
    assert.deepEqual(next, {
      url: "https://evil.example/",
      etag: '"x"',
      hash: "sha256:evil",
      agent_id: "agt_sitescan",
    });
    assert.equal(
      Object.prototype.hasOwnProperty.call(next, "smuggle"),
      false
    );
  });

  it("sanitizeHopInput drops extras from object path", () => {
    const s = sanitizeHopInput({
      url: "https://x/",
      hash: "h",
      agent_id: "a",
      CuNiMeta: "x",
    });
    assert.deepEqual(s, {
      url: "https://x/",
      hash: "h",
      agent_id: "a",
    });
  });
});

describe("reject.replay", () => {
  it("rejects hash already seen (not nonce/hop_id)", () => {
    const seen = new Set<string>();
    const text = chunk({
      url: "https://example.com/",
      etag: '"abc"',
      hash: "sha256:dead",
      agent_id: "agt_1",
    });
    assert.equal(evaluateHopGate(text, opts({ seenHashes: seen })).code, "admit");
    assert.equal(
      evaluateHopGate(text, opts({ seenHashes: seen })).code,
      "reject.replay"
    );
  });
});

describe("reject.agent", () => {
  it("rejects agent not on allowlist", () => {
    const text = chunk({
      url: "https://example.com/z",
      etag: '"z"',
      hash: "sha256:z",
      agent_id: "agt_other",
    });
    assert.equal(
      evaluateHopGate(text, opts({ allowedAgents: ["agt_1"] })).code,
      "reject.agent"
    );
  });
});

describe("reject.log TSV", () => {
  it("records ISO\\tcode\\tpreview lines mirroring agent-rider-c/reject.log", () => {
    evaluateHopGate(null, opts());
    const bad = chunk(
      {
        url: "https://evil.example/",
        etag: '"x"',
        hash: "sha256:evil",
        agent_id: "agt_sitescan",
      },
      ["smuggle=1"]
    );
    evaluateHopGate(bad, opts());
    evaluateHopGate(
      chunk({
        url: "https://example.com/z",
        etag: '"z"',
        hash: "sha256:z",
        agent_id: "agt_other",
      }),
      opts({ allowedAgents: ["agt_1"] })
    );

    const all = listRejectLog();
    assert.equal(all.length, 3);
    assert.ok(all.every((e) => e.code.startsWith("reject.")));

    const line = formatRejectLogLine(all[1]);
    const parts = line.split("\t");
    assert.equal(parts.length, 3);
    assert.equal(parts[0], "2026-09-17T04:00:00Z");
    assert.equal(parts[1], "reject.extra");
    assert.ok(!parts[2].includes("\n"));
    assert.ok(parts[2].length <= 120);

    const tsv = listRejectLogTsv();
    assert.ok(tsv.includes("reject.empty"));
    assert.ok(tsv.includes("reject.extra"));
    assert.ok(tsv.includes("reject.agent"));
    assert.equal(listRejectLog(1).length, 1);
    assert.equal(listRejectLog(1)[0].code, "reject.agent");
  });

  it("sanitizePreview truncates and flattens newlines", () => {
    const p = sanitizePreview("line1\nline2\n" + "x".repeat(200));
    assert.ok(!p.includes("\n"));
    assert.ok(p.length <= 120);
  });
});

describe("gate result wire", () => {
  it("is single exact-text code string (no JSON body)", () => {
    const text = chunk({
      url: "https://example.com/",
      hash: "sha256:1",
      agent_id: "a",
    });
    const r = evaluateHopGate(text, opts());
    assert.equal(formatHopGateCode(r.code), "admit");
    assert.equal(JSON.stringify(r.code), '"admit"');
    // wire-facing value is the bare code, not a JSON object
    assert.equal(formatHopGateCode(r.code).includes("{"), false);
  });
});

describe("durable reject log (KMS/CloudTrail match)", () => {
  it("defaults to ~/.chamber/reject.log", () => {
    assert.ok(DEFAULT_REJECT_LOG_FILE.endsWith(".chamber/reject.log"));
  });

  it("writes every reject to the file immediately, same TSV shape", () => {
    const dir = mkdtempSync(join(tmpdir(), "chamber-log-"));
    try {
      const file = join(dir, "reject.log");
      const text = chunk(
        {
          url: "https://evil.example/",
          etag: '"x"',
          hash: "sha256:evil",
          agent_id: "agt_sitescan",
        },
        ["smuggle=evil-blob-should-not-rehydrate"]
      );
      const r = evaluateHopGate(text, {
        now: fixedNow,
        seenHashes: new Set(),
        logFile: file,
      });
      assert.equal(r.code, "reject.extra");
      const body = readFileSync(file, "utf8");
      const lines = body.trim().split("\n");
      assert.equal(lines.length, 1);
      const parts = lines[0].split("\t");
      assert.equal(parts.length, 3);
      assert.equal(parts[0], "2026-09-17T04:00:00Z");
      assert.equal(parts[1], "reject.extra");
      assert.ok(parts[2].includes("smuggle"));
      assert.equal(parts[2].includes("evil-blob-should-not-rehydrate"), false);
      // in-memory log and file agree
      assert.equal(listRejectLog().length, 1);
      assert.equal(formatRejectLogLine(listRejectLog()[0]), lines[0]);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("survives a simulated restart: reset clears memory, load restores from file", () => {
    const dir = mkdtempSync(join(tmpdir(), "chamber-log-"));
    try {
      const file = join(dir, "nested", "reject.log");
      evaluateHopGate(null, {
        now: fixedNow,
        seenHashes: new Set(),
        logFile: file,
      });
      evaluateHopGate("CUNI SettleHop\nhop_id=x\n", {
        now: fixedNow,
        seenHashes: new Set(),
        logFile: file,
      });
      assert.equal(listRejectLog().length, 2);

      // simulate a server restart: in-memory state is gone
      resetHopGateState();
      assert.equal(listRejectLog().length, 0);
      assert.equal(listRejectLogTsv(), "");

      const loaded = loadPersistedRejectLog(file);
      assert.equal(loaded, 2);
      const all = listRejectLog();
      assert.equal(all.length, 2);
      assert.deepEqual(
        all.map((e) => e.code),
        ["reject.empty", "reject.extra"]
      );
      assert.ok(listRejectLogTsv().includes("reject.empty"));
      assert.ok(listRejectLogTsv().includes("reject.extra"));

      // loading twice does not duplicate
      assert.equal(loadPersistedRejectLog(file), 0);
      assert.equal(listRejectLog().length, 2);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("logFile: null writes nothing to disk", () => {
    const dir = mkdtempSync(join(tmpdir(), "chamber-log-"));
    try {
      const file = join(dir, "reject.log");
      evaluateHopGate(null, {
        now: fixedNow,
        seenHashes: new Set(),
        logFile: null,
      });
      assert.equal(existsSync(file), false);
      assert.equal(listRejectLog().length, 1); // in-memory still records it
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("appendRejectLog to an unwritable path never throws", () => {
    // Parent is a regular file, not a directory: mkdir/append fail fast
    // with ENOTDIR. NOTE: do NOT use a /proc path here — Node's recursive
    // mkdir spins forever on pseudo-filesystems (verified manually with
    // `timeout 10 node -e mkdirSync('/proc/x', {recursive:true})` → hang),
    // which is why the implementation uses a bounded manual ensureDir.
    const dir = mkdtempSync(join(tmpdir(), "chamber-log-"));
    try {
      const blocker = join(dir, "blocker");
      writeFileSync(blocker, "not a directory");
      assert.doesNotThrow(() =>
        appendRejectLog(
          { at: "2026-09-17T04:00:00Z", code: "reject.empty", preview: "" },
          { logFile: join(blocker, "reject.log") }
        )
      );
      // in-memory log still holds the entry
      assert.ok(listRejectLog().some((e) => e.code === "reject.empty"));
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
