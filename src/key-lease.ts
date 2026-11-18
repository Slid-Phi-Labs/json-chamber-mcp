/**
 * #25 — Key-lease revocation (Batch 4).
 *
 * Exported memory/secrets leave as CIPHERTEXT plus a short-lived KEY LEASE.
 * The recipient NEVER holds the key: the data-encryption key (DEK) is
 * wrapped under a lease key that lives only inside the owner's revocation
 * service (LeaseService). Every decryption goes through the service, which
 * unwraps the DEK only while the lease is live.
 *
 * Revocation is ONE act: revoke(leaseId) — or simply stop renewing — and
 * every copy of the bundle goes dark at lease expiry, because no copy holds
 * anything that can decrypt without the service. A lease that is revoked or
 * expired fails closed at unwrap time; there is no grace decryption.
 *
 * Honest limits (stated, not hidden):
 * - A recipient that decrypted while the lease was live could have cached
 *   the PLAINTEXT from that read. The lease kills future decryption, not
 *   copies of plaintext already lawfully read. What it guarantees: zero
 *   NEW decryptions from any copy after revocation/expiry.
 * - The service is the trust root: whoever holds the service's lease key
 *   can unwrap. Run it where the owner controls it; a compromised service
 *   is a compromised lease.
 * - Lease state is in-memory by default. A process restart drops all
 *   leases — which fails CLOSED (every bundle goes dark), never open.
 */

import {
  createCipheriv,
  createDecipheriv,
  createHash,
  randomBytes,
} from "node:crypto";

const LEASE_AAD = Buffer.from("chamber-lease-v1");
const WRAP_AAD = Buffer.from("chamber-lease-wrap-v1");

export type LeaseRecord = {
  leaseId: string;
  createdAt: number; // ms epoch
  expiresAt: number; // ms epoch
  revoked: boolean;
  revokedAt?: number;
};

export type LeasedBundle = {
  v: 1;
  leaseId: string;
  /** Lease expiry the bundle was issued under (informational; the service is authoritative). */
  expiresAt: number;
  nonce: string; // hex, data ciphertext
  tag: string; // hex, data ciphertext
  ct: string; // base64, data ciphertext
  wrappedNonce: string; // hex, DEK wrap
  wrappedTag: string; // hex, DEK wrap
  wrappedDek: string; // base64, DEK wrapped under the service lease key
};

/** The owner's revocation service. Holds the lease key; nothing else does. */
export class LeaseService {
  private readonly leaseKey: Buffer;
  private readonly leases = new Map<string, LeaseRecord>();

  constructor(leaseKey?: Buffer) {
    this.leaseKey = leaseKey ?? randomBytes(32);
  }

  /** Mint a lease that lives ttlMs from now. */
  createLease(ttlMs: number): LeaseRecord {
    if (!Number.isFinite(ttlMs) || ttlMs <= 0) {
      throw new Error("lease TTL must be a positive number of milliseconds");
    }
    const now = Date.now();
    const rec: LeaseRecord = {
      leaseId: `lease-${randomBytes(8).toString("hex")}`,
      createdAt: now,
      expiresAt: now + ttlMs,
      revoked: false,
    };
    this.leases.set(rec.leaseId, rec);
    return { ...rec };
  }

  /** Renew a live, unrevoked lease for a further ttlMs from now. */
  renew(leaseId: string, ttlMs: number): LeaseRecord {
    const rec = this.leases.get(leaseId);
    if (!rec) throw new Error(`unknown lease: ${leaseId}`);
    if (rec.revoked) throw new Error(`lease revoked: ${leaseId}`);
    if (Date.now() >= rec.expiresAt) {
      throw new Error(`lease expired: ${leaseId} — renewal refused`);
    }
    if (!Number.isFinite(ttlMs) || ttlMs <= 0) {
      throw new Error("lease TTL must be a positive number of milliseconds");
    }
    rec.expiresAt = Date.now() + ttlMs;
    return { ...rec };
  }

  /** THE revocation act. One call; every copy of every bundle on this lease goes dark at expiry (immediately, for decrypt purposes). */
  revoke(leaseId: string): LeaseRecord {
    const rec = this.leases.get(leaseId);
    if (!rec) throw new Error(`unknown lease: ${leaseId}`);
    rec.revoked = true;
    rec.revokedAt = Date.now();
    return { ...rec };
  }

  getLease(leaseId: string): LeaseRecord | undefined {
    const rec = this.leases.get(leaseId);
    return rec ? { ...rec } : undefined;
  }

  /** Live = known, not revoked, and now < expiresAt. */
  isLive(leaseId: string, now = Date.now()): boolean {
    const rec = this.leases.get(leaseId);
    return !!rec && !rec.revoked && now < rec.expiresAt;
  }

  /**
   * Unwrap a DEK. Throws unless the lease is live RIGHT NOW. This is the
   * only place the lease key is used — the recipient never sees it.
   */
  unwrapDek(leaseId: string, wrapped: {
    wrappedNonce: string;
    wrappedTag: string;
    wrappedDek: string;
  }): Buffer {
    const rec = this.leases.get(leaseId);
    if (!rec) throw new Error(`unknown lease: ${leaseId}`);
    if (rec.revoked) {
      throw new Error(`lease revoked: ${leaseId} — decryption refused`);
    }
    if (Date.now() >= rec.expiresAt) {
      throw new Error(`lease expired: ${leaseId} — decryption refused`);
    }
    const decipher = createDecipheriv(
      "aes-256-gcm",
      this.leaseKey,
      Buffer.from(wrapped.wrappedNonce, "hex")
    );
    decipher.setAAD(WRAP_AAD);
    decipher.setAuthTag(Buffer.from(wrapped.wrappedTag, "hex"));
    return Buffer.concat([
      decipher.update(Buffer.from(wrapped.wrappedDek, "base64")),
      decipher.final(),
    ]);
  }

  /** Wrap a DEK under the service lease key (export side only). */
  wrapDek(
    dek: Buffer
  ): { wrappedNonce: string; wrappedTag: string; wrappedDek: string } {
    const nonce = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", this.leaseKey, nonce);
    cipher.setAAD(WRAP_AAD);
    const wrapped = Buffer.concat([cipher.update(dek), cipher.final()]);
    return {
      wrappedNonce: nonce.toString("hex"),
      wrappedTag: cipher.getAuthTag().toString("hex"),
      wrappedDek: wrapped.toString("base64"),
    };
  }
}

/**
 * Export plaintext as a leased bundle. The caller keeps the bundle; the
 * DEK is wrapped under the service key and the service keeps the lease.
 * The recipient receives ciphertext + wrapped DEK and NO key.
 */
export function exportLeasedBundle(
  plaintext: Buffer,
  service: LeaseService,
  ttlMs: number
): LeasedBundle {
  const lease = service.createLease(ttlMs);
  const dek = randomBytes(32);
  const nonce = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", dek, nonce);
  cipher.setAAD(LEASE_AAD);
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const wrapped = service.wrapDek(dek);
  return {
    v: 1,
    leaseId: lease.leaseId,
    expiresAt: lease.expiresAt,
    nonce: nonce.toString("hex"),
    tag: cipher.getAuthTag().toString("hex"),
    ct: ct.toString("base64"),
    ...wrapped,
  };
}

/**
 * Decrypt a leased bundle. Goes through the revocation service every time:
 * revoked or expired lease = throw, no plaintext. A live lease decrypts.
 */
export function decryptLeasedBundle(
  bundle: LeasedBundle,
  service: LeaseService
): Buffer {
  if (!bundle || typeof bundle !== "object" || bundle.v !== 1) {
    throw new Error("unsupported leased bundle format");
  }
  if (typeof bundle.leaseId !== "string" || !bundle.leaseId) {
    throw new Error("leased bundle carries no lease id — decryption refused");
  }
  const dek = service.unwrapDek(bundle.leaseId, bundle);
  const decipher = createDecipheriv(
    "aes-256-gcm",
    dek,
    Buffer.from(bundle.nonce, "hex")
  );
  decipher.setAAD(LEASE_AAD);
  decipher.setAuthTag(Buffer.from(bundle.tag, "hex"));
  return Buffer.concat([
    decipher.update(Buffer.from(bundle.ct, "base64")),
    decipher.final(),
  ]);
}

/** Fingerprint of a bundle's ciphertext (for copy-tracking, never a key). */
export function bundleFingerprint(bundle: LeasedBundle): string {
  return createHash("sha256").update(bundle.ct, "base64").digest("hex");
}
