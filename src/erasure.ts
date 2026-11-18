/**
 * #33 — Erasure receipts (Batch 4).
 *
 * Deleting data returns a SIGNED receipt enumerating EVERY place a copy lived
 * (primary replicas, fragments, backups, snapshots, caches, indexes, derived
 * extracts) and the attestation from each place that it is gone — or, where
 * removal is impossible before a retention lock expires, a signed statement
 * of the exact expiry date.
 *
 * An erasure is NOT "done" until the receipt is complete: every registered
 * location must carry either a probe-verified removal attestation or a signed
 * retention-lock statement with an exact expiry. Any location with no answer
 * (adapter throws, times out, or its attestation fails verification) is
 * listed as an OPEN ITEM and the receipt is marked incomplete.
 *
 * Model: Chamber MCP holds no copy store of its own — the host application
 * registers its real copy locations (each location is an adapter with
 * plant/probe/erase). This module is the receipt machinery + a reference
 * in-memory location implementation used by the tests. A host that registers
 * no locations gets a receipt over zero locations (complete, vacuously);
 * registering a location and then having it go silent is what produces open
 * items — silence can never be read as "gone".
 *
 * Fail-closed throughout: an erase that throws, an attestation whose
 * signature does not verify, or a post-erase probe that still finds the
 * record all become open items, never silent success.
 */

import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { deriveKey, hmacSign, hmacVerify } from "./signing.js";

export const COPY_LOCATION_KINDS = [
  "primary",
  "fragment",
  "backup",
  "snapshot",
  "cache",
  "index",
  "derived",
] as const;

export type CopyLocationKind = (typeof COPY_LOCATION_KINDS)[number];

/** What a location returns when it actually removed the record. */
export type RemovalAttestation = {
  kind: "removed";
  locationId: string;
  locationKind: CopyLocationKind;
  recordId: string;
  removedAt: string; // ISO timestamp
  statement: string;
  sig: string; // HMAC over the attestation body, keyed by the location
};

/** What a location returns when a retention lock forbids removal for now. */
export type RetentionStatement = {
  kind: "retention-locked";
  locationId: string;
  locationKind: CopyLocationKind;
  recordId: string;
  issuedAt: string; // ISO timestamp
  retentionExpiresAt: string; // ISO timestamp — the exact expiry date
  reason: string;
  sig: string; // HMAC over the statement body, keyed by the location
};

export type LocationEraseOutcome = RemovalAttestation | RetentionStatement;

export type ErasureEntry =
  | { status: "removed"; attestation: RemovalAttestation; probeVerified: boolean }
  | { status: "retention-locked"; statement: RetentionStatement };

export type OpenItem = {
  locationId: string;
  locationKind: CopyLocationKind;
  recordId: string;
  reason: string; // "no-answer" | "attestation-invalid" | "removal-unverified"
  detail: string;
};

export type ErasureReceipt = {
  v: 1;
  receiptId: string;
  recordId: string;
  issuedAt: string;
  /** True only when every registered location resolved (removed or locked). */
  complete: boolean;
  entries: ErasureEntry[];
  openItems: OpenItem[];
  sig: string; // HMAC over the receipt body, keyed by the issuer key
};

/**
 * A place a copy can live. The host implements this against its real stores;
 * InMemoryCopyLocation below is the reference implementation.
 */
export interface CopyLocation {
  readonly id: string;
  readonly kind: CopyLocationKind;
  /** Independent probe: does the record still exist here right now? */
  probe(recordId: string): boolean;
  /** Remove the record. Throws when the location does not answer. */
  erase(recordId: string): LocationEraseOutcome;
  /** Verify one of this location's own signed statements. */
  verifyStatement(outcome: LocationEraseOutcome): boolean;
  /** Test/support hook: put a synthetic record here. */
  plant(recordId: string, data: Buffer): void;
}

const ISSUER_KEY = deriveKey("chamber-erasure-receipt-v1");

function receiptBody(r: Omit<ErasureReceipt, "sig">): unknown {
  const { sig: _sig, ...body } = r as ErasureReceipt & { sig?: string };
  void _sig;
  return body;
}

export function signReceipt(
  r: Omit<ErasureReceipt, "sig">
): ErasureReceipt {
  return { ...r, sig: hmacSign(ISSUER_KEY, receiptBody(r)) };
}

export function verifyReceiptSignature(r: ErasureReceipt): boolean {
  return hmacVerify(ISSUER_KEY, receiptBody(r), r.sig);
}

/**
 * Reference location: an in-memory map with a per-location signing key.
 * Options model the awkward real world:
 * - retentionUntil: erase() returns a signed retention statement until then.
 * - silent: erase() throws (location never answers) — produces an open item.
 */
export class InMemoryCopyLocation implements CopyLocation {
  readonly id: string;
  readonly kind: CopyLocationKind;
  private store = new Map<string, Buffer>();
  private readonly signKey: Buffer;
  private readonly retentionUntil?: Date;
  private readonly silent: boolean;

  constructor(
    id: string,
    kind: CopyLocationKind,
    opts: { retentionUntil?: Date; silent?: boolean; signKey?: Buffer } = {}
  ) {
    this.id = id;
    this.kind = kind;
    this.retentionUntil = opts.retentionUntil;
    this.silent = opts.silent ?? false;
    // Per-location key: explicit, else derived from the master + location id
    // so a location's attestations cannot be minted by another location.
    this.signKey =
      opts.signKey ??
      createHmac("sha256", deriveKey("chamber-erasure-location-v1"))
        .update(id, "utf8")
        .digest();
  }

  plant(recordId: string, data: Buffer): void {
    this.store.set(recordId, Buffer.from(data));
  }

  probe(recordId: string): boolean {
    return this.store.has(recordId);
  }

  erase(recordId: string): LocationEraseOutcome {
    if (this.silent) {
      throw new Error(`location ${this.id} did not answer erase`);
    }
    const now = new Date();
    if (this.retentionUntil && now < this.retentionUntil) {
      const body = {
        kind: "retention-locked" as const,
        locationId: this.id,
        locationKind: this.kind,
        recordId,
        issuedAt: now.toISOString(),
        retentionExpiresAt: this.retentionUntil.toISOString(),
        reason: `retention lock active until ${this.retentionUntil.toISOString()}`,
      };
      return { ...body, sig: hmacSign(this.signKey, body) };
    }
    this.store.delete(recordId);
    const body = {
      kind: "removed" as const,
      locationId: this.id,
      locationKind: this.kind,
      recordId,
      removedAt: now.toISOString(),
      statement: `record ${recordId} removed from ${this.kind} location ${this.id}`,
    };
    return { ...body, sig: hmacSign(this.signKey, body) };
  }

  verifyStatement(outcome: LocationEraseOutcome): boolean {
    const { sig, ...body } = outcome;
    void sig;
    try {
      const expected = hmacSign(this.signKey, body);
      return (
        typeof outcome.sig === "string" &&
        timingSafeEqual(
          Buffer.from(outcome.sig, "hex"),
          Buffer.from(expected, "hex")
        )
      );
    } catch {
      return false;
    }
  }
}

/** Registry of every place copies live + the erasure/receipt machinery. */
export class CopyRegistry {
  private locations: CopyLocation[] = [];

  register(location: CopyLocation): void {
    if (this.locations.some((l) => l.id === location.id)) {
      throw new Error(`copy location already registered: ${location.id}`);
    }
    this.locations.push(location);
  }

  get locationIds(): string[] {
    return this.locations.map((l) => l.id);
  }

  get locationCount(): number {
    return this.locations.length;
  }

  /** Plant the same synthetic record in every registered location. */
  plantEverywhere(recordId: string, data: Buffer): void {
    for (const loc of this.locations) loc.plant(recordId, data);
  }

  /** Independent probe of every location (used to verify a receipt). */
  probeEverywhere(recordId: string): Record<string, boolean> {
    const out: Record<string, boolean> = {};
    for (const loc of this.locations) {
      try {
        out[loc.id] = loc.probe(recordId);
      } catch {
        out[loc.id] = true; // probe failure reads as "still present"
      }
    }
    return out;
  }

  /**
   * Issue an erasure for a record across every registered location and
   * return the signed receipt. Complete only when no location is left open.
   */
  issueErasure(recordId: string): ErasureReceipt {
    const entries: ErasureEntry[] = [];
    const openItems: OpenItem[] = [];
    const issuedAt = new Date().toISOString();

    for (const loc of this.locations) {
      let outcome: LocationEraseOutcome;
      try {
        outcome = loc.erase(recordId);
      } catch (e) {
        openItems.push({
          locationId: loc.id,
          locationKind: loc.kind,
          recordId,
          reason: "no-answer",
          detail: e instanceof Error ? e.message : String(e),
        });
        continue;
      }
      if (!loc.verifyStatement(outcome)) {
        openItems.push({
          locationId: loc.id,
          locationKind: loc.kind,
          recordId,
          reason: "attestation-invalid",
          detail: "location statement signature did not verify",
        });
        continue;
      }
      if (outcome.kind === "retention-locked") {
        entries.push({ status: "retention-locked", statement: outcome });
        continue;
      }
      // Removal claimed: verify with an INDEPENDENT probe before believing it.
      let stillPresent: boolean;
      try {
        stillPresent = loc.probe(recordId);
      } catch {
        stillPresent = true;
      }
      if (stillPresent) {
        openItems.push({
          locationId: loc.id,
          locationKind: loc.kind,
          recordId,
          reason: "removal-unverified",
          detail: "location attested removal but an independent probe still finds the record",
        });
        continue;
      }
      entries.push({
        status: "removed",
        attestation: outcome,
        probeVerified: true,
      });
    }

    return signReceipt({
      v: 1,
      receiptId: `erasure-${randomBytes(8).toString("hex")}`,
      recordId,
      issuedAt,
      complete: openItems.length === 0,
      entries,
      openItems,
    });
  }

  /**
   * Verify a receipt: signature first, then every attestation's signature,
   * then an independent probe of every location the receipt claims is clean.
   * Returns false on ANY failure — a receipt is only as good as its weakest
   * attestation.
   */
  verifyReceipt(receipt: ErasureReceipt): boolean {
    if (!verifyReceiptSignature(receipt)) return false;
    if (receipt.complete && receipt.openItems.length > 0) return false;
    if (!receipt.complete && receipt.openItems.length === 0) return false;
    const byId = new Map(this.locations.map((l) => [l.id, l]));
    // Every registered location must appear exactly once: entry or open item.
    const accounted = new Set<string>();
    for (const e of receipt.entries) {
      const id =
        e.status === "removed"
          ? e.attestation.locationId
          : e.statement.locationId;
      if (accounted.has(id)) return false;
      accounted.add(id);
      const loc = byId.get(id);
      if (!loc) return false; // receipt names a location we do not know
      const outcome =
        e.status === "removed" ? e.attestation : e.statement;
      if (!loc.verifyStatement(outcome)) return false;
      if (e.status === "removed") {
        // Independent probe: the record must actually be gone.
        try {
          if (loc.probe(receipt.recordId)) return false;
        } catch {
          return false;
        }
      } else {
        // Retention statement must carry an exact, parseable expiry date.
        // (Expiry is judged against issuance time by the issuer, not by
        // the verifier — a receipt verified after the lock lapses is still
        // a true record of what was locked when.)
        const exp = Date.parse(e.statement.retentionExpiresAt);
        if (!Number.isFinite(exp)) return false;
      }
    }
    for (const o of receipt.openItems) {
      if (accounted.has(o.locationId)) return false;
      accounted.add(o.locationId);
      if (!byId.has(o.locationId)) return false;
    }
    if (accounted.size !== this.locations.length) return false;
    return true;
  }
}
