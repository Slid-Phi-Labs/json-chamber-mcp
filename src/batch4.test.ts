/**
 * Batch 4 tests — #33 erasure receipts, #25 key-lease revocation,
 * #31 transparency-log-verified reads (optional, default OFF).
 *
 * Evidence targets (see ~/workspace/55-exec/batch-4-chamber-evidence.md):
 * - #33: synthetic record planted in every copy location, erasure issued,
 *   receipt verified against independent probes of each location.
 * - #25: exported bundle revoked, decrypt attempted after lease expiry
 *   across all copies (target: zero successes); a live lease still decrypts.
 * - #31: tampered bytes refused (target: zero reads returning tampered
 *   data); valid reads pass; added read latency measured.
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import {
  CopyRegistry,
  InMemoryCopyLocation,
  verifyReceiptSignature,
  type CopyLocation,
  type CopyLocationKind,
  type LocationEraseOutcome,
} from "./erasure.js";
import {
  LeaseService,
  decryptLeasedBundle,
  exportLeasedBundle,
  type LeasedBundle,
} from "./key-lease.js";
import {
  TransparencyLog,
  VerifiedReadLayer,
  openWithTransparency,
  sealWithTransparency,
} from "./transparency-log.js";
import { chamberOpen, chamberSeal } from "./chamber.js";
import { deriveKey, hmacSign } from "./signing.js";

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

function fullRegistry(): CopyRegistry {
  const reg = new CopyRegistry();
  const kinds: CopyLocationKind[] = [
    "primary",
    "fragment",
    "backup",
    "snapshot",
    "cache",
    "index",
    "derived",
  ];
  for (const kind of kinds) {
    reg.register(new InMemoryCopyLocation(`${kind}-1`, kind));
  }
  return reg;
}

describe("#33 erasure receipts", () => {
  it("plants a record in every copy location, erases, receipt is complete and probe-verified", () => {
    const reg = fullRegistry();
    const record = Buffer.from('{"secret":"test-secret-for-erasure-receipt"}', "utf8");
    reg.plantEverywhere("rec-33", record);
    // Independent probes confirm the plant before erasure.
    const before = reg.probeEverywhere("rec-33");
    assert.equal(Object.values(before).filter(Boolean).length, 7);

    const receipt = reg.issueErasure("rec-33");
    assert.equal(receipt.complete, true);
    assert.equal(receipt.openItems.length, 0);
    assert.equal(receipt.entries.length, 7);
    assert.equal(
      receipt.entries.filter((e) => e.status === "removed").length,
      7
    );
    assert.equal(verifyReceiptSignature(receipt), true);
    assert.equal(reg.verifyReceipt(receipt), true);

    // Independent probes AFTER erasure: every location is clean.
    const after = reg.probeEverywhere("rec-33");
    assert.equal(Object.values(after).filter(Boolean).length, 0);
  });

  it("retention lock: locked location yields a signed statement with the exact expiry, receipt stays complete", () => {
    const reg = fullRegistry();
    const expiry = new Date(Date.now() + 24 * 3600 * 1000);
    reg.register(
      new InMemoryCopyLocation("backup-locked", "backup", {
        retentionUntil: expiry,
      })
    );
    reg.plantEverywhere("rec-33-lock", Buffer.from("locked-data", "utf8"));
    const receipt = reg.issueErasure("rec-33-lock");
    assert.equal(receipt.complete, true);
    assert.equal(receipt.openItems.length, 0);
    const locked = receipt.entries.filter(
      (e) => e.status === "retention-locked"
    );
    assert.equal(locked.length, 1);
    assert.equal(
      locked[0].status === "retention-locked" &&
        locked[0].statement.retentionExpiresAt,
      expiry.toISOString()
    );
    // The locked copy is still present (correctly — the lock forbids removal).
    assert.equal(reg.probeEverywhere("rec-33-lock")["backup-locked"], true);
    assert.equal(reg.verifyReceipt(receipt), true);
  });

  it("silent location: no answer becomes an open item and the receipt is NOT complete", () => {
    const reg = fullRegistry();
    reg.register(
      new InMemoryCopyLocation("cache-silent", "cache", { silent: true })
    );
    reg.plantEverywhere("rec-33-silent", Buffer.from("x", "utf8"));
    const receipt = reg.issueErasure("rec-33-silent");
    assert.equal(receipt.complete, false);
    assert.equal(receipt.openItems.length, 1);
    assert.equal(receipt.openItems[0].reason, "no-answer");
    assert.equal(receipt.openItems[0].locationId, "cache-silent");
    // The receipt itself is honestly incomplete: signature + accounting verify.
    assert.equal(reg.verifyReceipt(receipt), true);
  });

  it("lying location: attested removal that an independent probe contradicts becomes an open item", () => {
    // A location that signs a removal attestation but keeps the record.
    const key = createHmac(
      "sha256",
      deriveKey("chamber-erasure-location-v1")
    )
      .update("cache-liar", "utf8")
      .digest();
    const liarStore = new Map<string, Buffer>([
      ["rec-33-liar", Buffer.from("still-here", "utf8")],
    ]);
    const liar: CopyLocation = {
      id: "cache-liar",
      kind: "cache",
      probe(recordId: string) {
        return liarStore.has(recordId);
      },
      erase(recordId: string): LocationEraseOutcome {
        // Claims removal; does NOT delete.
        const body = {
          kind: "removed" as const,
          locationId: this.id,
          locationKind: this.kind,
          recordId,
          removedAt: new Date().toISOString(),
          statement: "removed (lie)",
        };
        return { ...body, sig: hmacSign(key, body) };
      },
      verifyStatement(outcome: LocationEraseOutcome): boolean {
        const { sig, ...body } = outcome;
        void sig;
        return hmacSign(key, body) === outcome.sig;
      },
      plant(recordId: string, data: Buffer): void {
        liarStore.set(recordId, Buffer.from(data));
      },
    };
    const reg = new CopyRegistry();
    reg.register(liar);
    const receipt = reg.issueErasure("rec-33-liar");
    assert.equal(receipt.complete, false);
    assert.equal(receipt.openItems.length, 1);
    assert.equal(receipt.openItems[0].reason, "removal-unverified");
  });

  it("tampered receipt or attestation fails verification", () => {
    const reg = fullRegistry();
    reg.plantEverywhere("rec-33-tamper", Buffer.from("t", "utf8"));
    const receipt = reg.issueErasure("rec-33-tamper");
    assert.equal(reg.verifyReceipt(receipt), true);
    const badSig = { ...receipt, sig: "00".repeat(32) };
    assert.equal(reg.verifyReceipt(badSig), false);
    const mutated = JSON.parse(JSON.stringify(receipt)) as typeof receipt;
    const first = mutated.entries[0];
    if (first.status === "removed") {
      first.attestation.statement = "forged statement";
    }
    assert.equal(reg.verifyReceipt(mutated), false);
  });
});

describe("#25 key-lease revocation", () => {
  it("live lease decrypts, byte-exact", () => {
    const svc = new LeaseService();
    const plain = Buffer.from('{"memory":"exported-secret"}', "utf8");
    const bundle = exportLeasedBundle(plain, svc, 60_000);
    assert.deepEqual(decryptLeasedBundle(bundle, svc), plain);
  });

  it("revoke + expiry: ZERO successes decrypting any copy after expiry", async () => {
    const svc = new LeaseService();
    const plain = Buffer.from("revocation-target", "utf8");
    const bundle = exportLeasedBundle(plain, svc, 150);
    // Three copies of the same bundle (same lease).
    const copies: LeasedBundle[] = [
      bundle,
      JSON.parse(JSON.stringify(bundle)) as LeasedBundle,
      JSON.parse(JSON.stringify(bundle)) as LeasedBundle,
    ];
    // Live lease still decrypts before revocation.
    assert.deepEqual(decryptLeasedBundle(copies[0], svc), plain);
    // THE revocation act.
    svc.revoke(bundle.leaseId);
    // Decrypt refuses immediately after revocation, before expiry.
    assert.throws(() => decryptLeasedBundle(copies[1], svc), /lease revoked/);
    await sleep(250); // past the 150ms lease expiry
    let successes = 0;
    for (const copy of copies) {
      try {
        decryptLeasedBundle(copy, svc);
        successes++;
      } catch {
        // expected: revoked or expired
      }
    }
    assert.equal(successes, 0);
  });

  it("expiry without revocation also goes dark (stop renewing = dark)", async () => {
    const svc = new LeaseService();
    const bundle = exportLeasedBundle(Buffer.from("short-lease", "utf8"), svc, 100);
    assert.deepEqual(
      decryptLeasedBundle(bundle, svc).toString("utf8"),
      "short-lease"
    );
    await sleep(200);
    assert.throws(() => decryptLeasedBundle(bundle, svc), /lease expired/);
  });

  it("renewal keeps a live lease decrypting past its original expiry", async () => {
    const svc = new LeaseService();
    const bundle = exportLeasedBundle(Buffer.from("renew-me", "utf8"), svc, 200);
    await sleep(100);
    svc.renew(bundle.leaseId, 5_000);
    await sleep(250); // past the ORIGINAL 200ms expiry
    assert.deepEqual(
      decryptLeasedBundle(bundle, svc).toString("utf8"),
      "renew-me"
    );
    // Renewal of a revoked or expired lease is refused.
    svc.revoke(bundle.leaseId);
    assert.throws(() => svc.renew(bundle.leaseId, 5_000), /lease revoked/);
  });

  it("tampered bundle and unknown lease fail closed", () => {
    const svc = new LeaseService();
    const bundle = exportLeasedBundle(Buffer.from("tamper", "utf8"), svc, 60_000);
    const tampered = { ...bundle };
    const pos = Math.floor(tampered.ct.length / 2);
    tampered.ct =
      tampered.ct.slice(0, pos) +
      (tampered.ct[pos] === "A" ? "B" : "A") +
      tampered.ct.slice(pos + 1);
    assert.throws(
      () => decryptLeasedBundle(tampered, svc),
      /unable to authenticate data|Unsupported state/
    );
    const unknown = { ...bundle, leaseId: "lease-deadbeefdeadbeef" };
    assert.throws(() => decryptLeasedBundle(unknown, svc), /unknown lease/);
  });
});

describe("#31 transparency-log-verified reads (optional, default OFF)", () => {
  it("valid reads pass: sealed + logged content opens byte-exact", () => {
    const log = new TransparencyLog();
    const plain = Buffer.from('{"verified":true}', "utf8");
    const { sealed, secondShare } = sealWithTransparency(plain, log);
    assert.deepEqual(openWithTransparency(sealed, secondShare, log), plain);
  });

  it("inclusion proofs verify for every leaf after many appends", () => {
    const log = new TransparencyLog();
    for (let i = 0; i < 33; i++) {
      sealWithTransparency(Buffer.from(`item-${i}`, "utf8"), log);
    }
    assert.equal(log.size, 33);
    for (let i = 0; i < 33; i++) {
      assert.equal(log.verifyInclusion(log.inclusionProof(i)), true);
    }
  });

  it("tampered bytes are refused: ZERO reads return tampered data", () => {
    const log = new TransparencyLog();
    const plain = Buffer.from('{"tamper":"target"}', "utf8");
    const { sealed, secondShare } = sealWithTransparency(plain, log);
    // Tamper the ciphertext inside the logged blob.
    const tampered = { ...sealed };
    const pos = Math.floor(tampered.ct.length / 2);
    tampered.ct =
      tampered.ct.slice(0, pos) +
      (tampered.ct[pos] === "A" ? "B" : "A") +
      tampered.ct.slice(pos + 1);
    let servedTampered = 0;
    try {
      openWithTransparency(tampered, secondShare, log);
      servedTampered++;
    } catch {
      // refused — GCM auth fails before any data is served
    }
    assert.equal(servedTampered, 0);
  });

  it("content never logged is refused (absent hash = read refused)", () => {
    const log = new TransparencyLog();
    // Sealed WITHOUT the log — hash was never appended.
    const { sealed, secondShare } = chamberSeal(
      Buffer.from("never-logged", "utf8")
    );
    assert.throws(
      () => openWithTransparency(sealed, secondShare, log),
      /content hash absent from the log — read refused/
    );
    // Plain open still works: the mode is opt-in, the blob itself is fine.
    assert.equal(
      chamberOpen(sealed, secondShare).toString("utf8"),
      "never-logged"
    );
  });

  it("forked log: bad tree-head signature or wrong-key proof fails verification", () => {
    const log = new TransparencyLog();
    sealWithTransparency(Buffer.from("fork-target", "utf8"), log);
    const proof = log.inclusionProof(0);
    assert.equal(log.verifyInclusion(proof), true);
    // Tampered signature.
    assert.equal(
      log.verifyInclusion({ ...proof, treeHeadSig: "00".repeat(64) }),
      false
    );
    // Same proof checked against a DIFFERENT log (different keypair) fails.
    const otherLog = new TransparencyLog();
    otherLog.restoreLeaves(log.serializeLeaves());
    assert.equal(otherLog.verifyInclusion(proof), false);
    // Tampered root.
    assert.equal(
      log.verifyInclusion({
        ...proof,
        treeHead: { ...proof.treeHead, root: "00".repeat(32) },
      }),
      false
    );
  });

  it("mode is OFF by default: no log consulted, no hash appended", () => {
    const log = new TransparencyLog();
    const layer = new VerifiedReadLayer(log); // enabled defaults false
    assert.equal(layer.enabled, false);
    const plain = Buffer.from("default-off", "utf8");
    const { sealed, secondShare } = layer.seal(plain) as {
      sealed: ReturnType<typeof chamberSeal>["sealed"];
      secondShare: string;
    };
    assert.equal(log.size, 0); // nothing appended while OFF
    assert.deepEqual(layer.open(sealed, secondShare), plain);
    // Enabled without a log refuses rather than silently downgrading.
    const noLog = new VerifiedReadLayer(null, true);
    assert.throws(() => noLog.seal(plain), /no log configured — seal refused/);
    assert.throws(
      () => noLog.open(sealed, secondShare),
      /no log configured — read refused/
    );
    // Enabled with a log: seal appends, open verifies.
    const on = new VerifiedReadLayer(log, true);
    const res = on.seal(plain);
    assert.equal(log.size, 1);
    assert.equal("contentHash" in res, true);
    assert.deepEqual(
      on.open(res.sealed, res.secondShare),
      plain
    );
  });

  it("latency: measures added read latency of verified vs plain open", () => {
    const log = new TransparencyLog();
    const plain = Buffer.from(
      JSON.stringify({ payload: "latency-probe", n: 12345 }),
      "utf8"
    );
    const { sealed, secondShare } = sealWithTransparency(plain, log);
    const N = 50;
    const time = (fn: () => void): number => {
      const t0 = process.hrtime.bigint();
      for (let i = 0; i < N; i++) fn();
      const t1 = process.hrtime.bigint();
      return Number(t1 - t0) / 1e6 / N; // ms per op
    };
    const plainMs = time(() => {
      chamberOpen(sealed, secondShare);
    });
    const verifiedMs = time(() => {
      openWithTransparency(sealed, secondShare, log);
    });
    // Sanity: both paths actually ran and returned the same bytes.
    assert.deepEqual(openWithTransparency(sealed, secondShare, log), plain);
    assert.ok(Number.isFinite(plainMs) && plainMs > 0);
    assert.ok(Number.isFinite(verifiedMs) && verifiedMs > 0);
    // Report for the evidence file (read from test output).
    console.log(
      `LATENCY_MEASUREMENT plain_open_ms=${plainMs.toFixed(4)} ` +
        `verified_open_ms=${verifiedMs.toFixed(4)} ` +
        `added_ms=${(verifiedMs - plainMs).toFixed(4)} ` +
        `overhead_pct=${(((verifiedMs - plainMs) / plainMs) * 100).toFixed(1)}% ` +
        `iterations=${N} log_size=${log.size}`
    );
  });
});
