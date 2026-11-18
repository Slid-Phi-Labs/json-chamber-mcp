/**
 * License gate tests — G-C04 / G-C05 / G-M07.
 *
 * Hermetic: HOME is redirected to a temp dir and CHAMBER_MASTER_SECRET
 * is set to a test-only secret BEFORE license.js is imported (dynamic
 * import — static imports hoist above the env assignments). The real
 * ~/.chamber is never touched, and no test depends on ambient env.
 *
 * Signing helper mirrors license.ts exactly: sorted-key JSON + HMAC-
 * SHA256 under the master secret (raw bytes; the test secret is >32).
 */

import { describe, it, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import {
  existsSync,
  mkdirSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const TEST_HOME = join(
  tmpdir(),
  `chamber-license-test-${process.pid}-${Date.now()}`
);
mkdirSync(TEST_HOME, { recursive: true });
process.env.HOME = TEST_HOME;
const TEST_SECRET = "license-test-master-secret-0123456789abcdef";
process.env.CHAMBER_MASTER_SECRET = TEST_SECRET;
delete process.env.JSON_CHAMBER_MASTER;
delete process.env.TRU8_MASTER_SECRET;
delete process.env.VERIFIEDDR_API_KEY;

const { LicenseManager, EVAL_SECONDS, PURCHASE_URL } = await import(
  "./license.js"
);

const CHAMBER_DIR = join(TEST_HOME, ".chamber");
const LICENSE_FILE = join(CHAMBER_DIR, "license.json");
const KILL_FILE = join(CHAMBER_DIR, "KILLED");

function signPayload(payload: Record<string, unknown>): string {
  const msg = JSON.stringify(payload, Object.keys(payload).sort());
  return createHmac("sha256", Buffer.from(TEST_SECRET, "utf8"))
    .update(msg)
    .digest("hex");
}

function writeLicense(payload: Record<string, unknown>): void {
  mkdirSync(CHAMBER_DIR, { recursive: true });
  writeFileSync(
    LICENSE_FILE,
    JSON.stringify({ ...payload, sig: signPayload(payload) }, null, 2)
  );
}

function evalPayload(
  overrides: Record<string, unknown> = {}
): Record<string, unknown> {
  const now = Math.floor(Date.now() / 1000);
  return {
    type: "eval",
    product: "json-chamber",
    first_run: now - 100,
    eval_expires: now + EVAL_SECONDS,
    purchased: false,
    device_hash: "testdevicehash00",
    ...overrides,
  };
}

function wipe(): void {
  rmSync(CHAMBER_DIR, { recursive: true, force: true });
}

beforeEach(() => {
  wipe();
  process.env.CHAMBER_MASTER_SECRET = TEST_SECRET;
  delete process.env.JSON_CHAMBER_MASTER;
  delete process.env.TRU8_MASTER_SECRET;
  delete process.env.VERIFIEDDR_API_KEY;
});

describe("G-C04 — no substring unlock, no bypass hint", () => {
  for (const key of [
    "vdr_purchased_anything",
    "my-pro-key-123",
    "live_abcdef",
    "PRO",
  ]) {
    it(`VERIFIEDDR_API_KEY=${JSON.stringify(key)} does not purchase`, () => {
      process.env.VERIFIEDDR_API_KEY = key;
      const s = new LicenseManager().check();
      assert.equal(s.alive, true);
      assert.equal(s.status, "eval");
    });
  }

  it("a signed purchased license still unlocks (legitimate path)", () => {
    writeLicense(evalPayload({ purchased: true }));
    const s = new LicenseManager().check();
    assert.equal(s.alive, true);
    assert.equal(s.status, "purchased");
    assert.doesNotThrow(() => new LicenseManager().requireAlive());
  });

  it("the failure banner never names a key bypass", () => {
    const now = Math.floor(Date.now() / 1000);
    writeLicense(evalPayload({ eval_expires: now - 10 }));
    assert.throws(
      () => new LicenseManager().requireAlive(),
      (err: unknown) => {
        const msg = err instanceof Error ? err.message : String(err);
        assert.equal(msg.includes("VERIFIEDDR"), false);
        assert.equal(msg.includes("vdr_"), false);
        assert.equal(/set .*key to/i.test(msg), false);
        assert.equal(msg.includes(PURCHASE_URL), true);
        return true;
      }
    );
  });
});

describe("G-C05 — no hardcoded demo secret; fail closed", () => {
  it("no master secret env → dead, no license file, no KILLED", () => {
    delete process.env.CHAMBER_MASTER_SECRET;
    delete process.env.JSON_CHAMBER_MASTER;
    delete process.env.TRU8_MASTER_SECRET;
    const s = new LicenseManager().check();
    assert.equal(s.alive, false);
    assert.equal(s.status, "dead");
    assert.match(s.reason ?? "", /master secret/i);
    assert.equal(existsSync(LICENSE_FILE), false);
    assert.equal(existsSync(KILL_FILE), false);
  });

  it("with a configured secret, the eval license is created and signed", () => {
    const s = new LicenseManager().check();
    assert.equal(s.alive, true);
    assert.equal(s.status, "eval");
    const raw = JSON.parse(readFileSync(LICENSE_FILE, "utf8"));
    const { sig, ...data } = raw;
    assert.equal(sig, signPayload(data));
  });

  it("the other env aliases also work (JSON_CHAMBER_MASTER)", () => {
    delete process.env.CHAMBER_MASTER_SECRET;
    process.env.JSON_CHAMBER_MASTER = TEST_SECRET;
    const s = new LicenseManager().check();
    assert.equal(s.alive, true);
    assert.equal(s.status, "eval");
  });
});

describe("G-M07 — KILLED is recoverable; purchase first; private files", () => {
  it("KILLED + valid purchased license → alive, marker cleared", () => {
    writeLicense(evalPayload({ purchased: true }));
    writeFileSync(KILL_FILE, "expired");
    const s = new LicenseManager().check();
    assert.equal(s.alive, true);
    assert.equal(s.status, "purchased");
    assert.equal(existsSync(KILL_FILE), false);
  });

  it("KILLED + unexpired eval license → still dead", () => {
    writeLicense(evalPayload());
    writeFileSync(KILL_FILE, "expired");
    const s = new LicenseManager().check();
    assert.equal(s.alive, false);
    assert.equal(s.status, "dead");
  });

  it("expiry writes KILLED; a later signed purchase revives", () => {
    const now = Math.floor(Date.now() / 1000);
    writeLicense(evalPayload({ eval_expires: now - 10 }));
    const dead1 = new LicenseManager().check();
    assert.equal(dead1.alive, false);
    assert.equal(existsSync(KILL_FILE), true);

    writeLicense(evalPayload({ purchased: true }));
    const s = new LicenseManager().check();
    assert.equal(s.alive, true);
    assert.equal(s.status, "purchased");
    assert.equal(existsSync(KILL_FILE), false);
  });

  it("signature mismatch writes KILLED; kill persists for eval, purchase revives", () => {
    writeLicense(evalPayload());
    const raw = JSON.parse(readFileSync(LICENSE_FILE, "utf8"));
    raw.purchased = true; // tamper without re-signing
    writeFileSync(LICENSE_FILE, JSON.stringify(raw, null, 2));
    const dead1 = new LicenseManager().check();
    assert.equal(dead1.alive, false);
    assert.match(dead1.reason ?? "", /signature mismatch/);
    assert.equal(existsSync(KILL_FILE), true);

    // A fresh valid EVAL license does not clear a tamper kill.
    writeLicense(evalPayload());
    assert.equal(new LicenseManager().check().alive, false);

    // A valid PURCHASED license does.
    writeLicense(evalPayload({ purchased: true }));
    const s = new LicenseManager().check();
    assert.equal(s.alive, true);
    assert.equal(s.status, "purchased");
    assert.equal(existsSync(KILL_FILE), false);
  });

  it("manual recovery works: delete KILLED (+ license) → fresh eval", () => {
    const now = Math.floor(Date.now() / 1000);
    writeLicense(evalPayload({ eval_expires: now - 10 }));
    assert.equal(new LicenseManager().check().alive, false);
    assert.equal(existsSync(KILL_FILE), true);
    rmSync(KILL_FILE);
    rmSync(LICENSE_FILE);
    const s = new LicenseManager().check();
    assert.equal(s.alive, true);
    assert.equal(s.status, "eval");
  });

  it("~/.chamber is 0700, license.json and KILLED are 0600", () => {
    const s = new LicenseManager().check();
    assert.equal(s.alive, true);
    assert.equal(statSync(CHAMBER_DIR).mode & 0o777, 0o700);
    assert.equal(statSync(LICENSE_FILE).mode & 0o777, 0o600);

    const now = Math.floor(Date.now() / 1000);
    writeLicense(evalPayload({ eval_expires: now - 10 }));
    assert.equal(new LicenseManager().check().alive, false);
    assert.equal(statSync(KILL_FILE).mode & 0o777, 0o600);
    // Existing loose files are tightened on the next load.
    assert.equal(statSync(LICENSE_FILE).mode & 0o777, 0o600);
  });
});
