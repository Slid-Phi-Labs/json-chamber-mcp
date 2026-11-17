/**
 * Chamber v2 seal/open tests: two-share custody (KMS match).
 * Invariants: blob alone does NOT open; master alone does NOT open;
 * correct both shares open; wrong second share fails closed; v1 blobs are
 * rejected; tamper fails closed.
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { createDecipheriv, createHash, randomBytes } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import {
  chamberSeal,
  chamberOpen,
  phiSplit,
  phiUnsplit,
  type SealedBlob,
} from "./chamber.js";

function wordsOf(text: string): string[] {
  return text.trim().split(/\s+/);
}

describe("phiSplit / phiUnsplit", () => {
  it("round-trips random 32-byte keys", () => {
    for (let i = 0; i < 10; i++) {
      const key = randomBytes(32);
      const [k, r] = phiSplit(key);
      assert.deepEqual(phiUnsplit(k, r), key);
    }
  });

  it("a wrong second share reconstructs a different key (never the original)", () => {
    const key = randomBytes(32);
    const [k, r] = phiSplit(key);
    const rBad = Buffer.from(r);
    rBad[0] ^= 0x01;
    assert.notDeepEqual(phiUnsplit(k, rBad), key);
  });
});

describe("chamberSeal v2 shape", () => {
  it("returns a v2 blob with no r_words and a 24-word second share", () => {
    const { sealed, secondShare } = chamberSeal(Buffer.from('{"a":1}', "utf8"));
    assert.equal(sealed.v, 2);
    assert.equal(sealed.algo, "chamber-aes256gcm-phi");
    assert.equal("r_words" in sealed, false);
    assert.equal(wordsOf(sealed.k_words).length, 24);
    assert.equal(wordsOf(secondShare).length, 24);
    assert.equal(sealed.orig_len, 7);
  });

  it("seals a fresh random session key each time (same plaintext, different ct)", () => {
    const plain = Buffer.from("same plaintext", "utf8");
    const a = chamberSeal(plain);
    const b = chamberSeal(plain);
    assert.notEqual(a.sealed.ct, b.sealed.ct);
    assert.notEqual(a.secondShare, b.secondShare);
  });
});

describe("chamberOpen two-share custody", () => {
  it("opens with the correct both shares, byte-exact", () => {
    const plain = Buffer.from('{"key":"value","n":42}', "utf8");
    const { sealed, secondShare } = chamberSeal(plain);
    assert.deepEqual(chamberOpen(sealed, secondShare), plain);
  });

  it("opens plain text (non-JSON) with the correct both shares", () => {
    const plain = Buffer.from("hello, second custodian", "utf8");
    const { sealed, secondShare } = chamberSeal(plain);
    assert.equal(chamberOpen(sealed, secondShare).toString("utf8"), "hello, second custodian");
  });

  it("blob alone does NOT open — second share missing fails closed", () => {
    const { sealed } = chamberSeal(Buffer.from("secret", "utf8"));
    assert.throws(
      () => chamberOpen(sealed, ""),
      /second share required/
    );
    assert.throws(
      () => chamberOpen(sealed, undefined as unknown as string),
      /second share required/
    );
  });

  it("wrong second share (valid words, wrong share) fails closed via GCM", () => {
    const { sealed } = chamberSeal(Buffer.from("secret", "utf8"));
    const other = chamberSeal(Buffer.from("different secret", "utf8"));
    assert.throws(
      () => chamberOpen(sealed, other.secondShare),
      /unable to authenticate data|Unsupported state/
    );
  });

  it("garbage second share (words outside the list) fails closed with a clear error", () => {
    const { sealed } = chamberSeal(Buffer.from("secret", "utf8"));
    const garbage = Array(24).fill("notaword").join(" ");
    assert.throws(() => chamberOpen(sealed, garbage), /invalid second share/);
  });

  it("short second share (wrong word count) fails closed", () => {
    const { sealed, secondShare } = chamberSeal(Buffer.from("secret", "utf8"));
    const short = wordsOf(secondShare).slice(0, 12).join(" ");
    assert.throws(() => chamberOpen(sealed, short), /expected 24 words/);
  });

  it("master secret alone does NOT open — v1-style master-derived key fails GCM under both AADs", () => {
    const master = Buffer.from("walkthrough-demo-master-secret-32bytes!", "utf8");
    const { sealed } = chamberSeal(Buffer.from("secret", "utf8"));
    // v1 derivation, exactly as the old code did it
    const derived = createHash("sha256").update(master).update("chamber-phi-v1").digest();
    for (const aad of ["chamber-v1", "chamber-v2"]) {
      assert.throws(() => {
        const d = createDecipheriv(
          "aes-256-gcm",
          derived,
          Buffer.from(sealed.nonce, "hex")
        );
        d.setAAD(Buffer.from(aad));
        d.setAuthTag(Buffer.from(sealed.tag, "hex"));
        Buffer.concat([d.update(Buffer.from(sealed.ct, "base64")), d.final()]);
      }, /unable to authenticate data|Unsupported state/);
    }
  });

  it("tamper — one flipped ciphertext byte fails closed", () => {
    const { sealed, secondShare } = chamberSeal(
      Buffer.from('{"receipt":true}', "utf8")
    );
    const t = { ...sealed };
    const pos = Math.floor(t.ct.length / 2);
    const ch = t.ct[pos];
    t.ct = t.ct.slice(0, pos) + (ch === "A" ? "B" : "A") + t.ct.slice(pos + 1);
    assert.throws(
      () => chamberOpen(t, secondShare),
      /unable to authenticate data|Unsupported state/
    );
  });
});

describe("v1 blobs are rejected, never opened", () => {
  it("rejects a synthetic v1-shaped blob (both shares embedded)", () => {
    const { sealed, secondShare } = chamberSeal(Buffer.from("secret", "utf8"));
    const v1: SealedBlob = { ...sealed, v: 1, r_words: secondShare };
    assert.throws(() => chamberOpen(v1, secondShare), /v1 blob rejected/);
    assert.throws(() => chamberOpen(v1, ""), /v1 blob rejected/);
  });

  it("rejects a v2 blob that carries r_words", () => {
    const { sealed, secondShare } = chamberSeal(Buffer.from("secret", "utf8"));
    const bad: SealedBlob = { ...sealed, r_words: secondShare };
    assert.throws(() => chamberOpen(bad, secondShare), /must not carry r_words/);
  });

  it("rejects an unknown format version", () => {
    const { sealed, secondShare } = chamberSeal(Buffer.from("secret", "utf8"));
    const bad: SealedBlob = { ...sealed, v: 99 };
    assert.throws(() => chamberOpen(bad, secondShare), /unsupported chamber format/);
  });

  it("rejects the real saved v1 blob from the 2026-11-17 comparison run", () => {
    const path = "/tmp/chamber-compare/s2-receipt.sealed.json";
    if (!existsSync(path)) {
      // Evidence file absent on this machine — the synthetic v1 test above covers it.
      return;
    }
    const v1 = JSON.parse(readFileSync(path, "utf8")) as SealedBlob;
    assert.equal(v1.v, 1);
    assert.equal(typeof v1.r_words, "string");
    assert.throws(() => chamberOpen(v1, v1.r_words as string), /v1 blob rejected/);
  });
});
