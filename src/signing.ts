/**
 * Shared signing helpers for the Batch 4 Chamber features (erasure receipts,
 * key leases, transparency log).
 *
 * Signing keys are derived from the Chamber master secret — resolved exactly
 * the way license.ts resolves it (CHAMBER_MASTER_SECRET / JSON_CHAMBER_MASTER
 * / TRU8_MASTER_SECRET env). There is no default master secret: without one
 * of those env vars the module fails closed (throws), exactly like
 * license.ts. The walkthrough sets the secret explicitly via env; nothing
 * in this module invents one. Derivation is per-purpose (HKDF-style:
 * SHA-256(master || purpose)) so a key minted for one feature cannot mint
 * another feature's statements.
 *
 * The transparency log is the exception: its tree head must be verifiable by
 * anyone holding the log's public key, so it uses Ed25519 (see
 * transparency-log.ts), not HMAC.
 */

import { createHash, createHmac, timingSafeEqual } from "node:crypto";

export function masterSecret(): string {
  const raw =
    process.env.CHAMBER_MASTER_SECRET ||
    process.env.JSON_CHAMBER_MASTER ||
    process.env.TRU8_MASTER_SECRET;
  if (!raw) {
    // Fail closed, exactly like license.ts: never fall back to a shipped
    // demo secret. Anyone who can read the repo could mint statements
    // with a hardcoded secret.
    throw new Error(
      "no Chamber master secret configured — set CHAMBER_MASTER_SECRET " +
        "(or JSON_CHAMBER_MASTER / TRU8_MASTER_SECRET)"
    );
  }
  return raw;
}

/** Purpose-separated HMAC key: SHA-256(master || "\0" || purpose). */
export function deriveKey(purpose: string): Buffer {
  return createHash("sha256")
    .update(masterSecret(), "utf8")
    .update("\0", "utf8")
    .update(purpose, "utf8")
    .digest();
}

/** Canonical JSON: sorted keys, no whitespace. Deterministic across runs. */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value) ?? "null";
  }
  if (Array.isArray(value)) {
    return `[${value.map(canonicalJson).join(",")}]`;
  }
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  return `{${keys
    .map((k) => `${JSON.stringify(k)}:${canonicalJson(obj[k])}`)
    .join(",")}}`;
}

export function hmacSign(key: Buffer, payload: unknown): string {
  return createHmac("sha256", key)
    .update(canonicalJson(payload), "utf8")
    .digest("hex");
}

export function hmacVerify(key: Buffer, payload: unknown, sig: string): boolean {
  if (typeof sig !== "string" || sig.length !== 64) return false;
  const expected = hmacSign(key, payload);
  try {
    return timingSafeEqual(Buffer.from(sig, "hex"), Buffer.from(expected, "hex"));
  } catch {
    return false;
  }
}
