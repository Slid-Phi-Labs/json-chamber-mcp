/**
 * #31 — Transparency-log-verified reads, OPTIONAL mode, default OFF (Batch 4).
 *
 * At WRITE time the SHA-256 content hash is appended to an append-only
 * Merkle-tree log (RFC 6962-style: leaf = SHA256(0x00 || hash),
 * node = SHA256(0x01 || left || right)); the append returns a signed
 * inclusion promise. At READ time the layer recomputes the content hash,
 * fetches an inclusion proof, and checks it against the log's SIGNED tree
 * head before serving anything.
 *
 * Fail-closed: absent hash = read refused; tree-head signature invalid =
 * read refused; inclusion proof that does not verify = read refused.
 * A tampered byte changes the content hash, so tampered data can never
 * produce a valid proof — the read is refused, never served.
 *
 * The tree head is signed with Ed25519 so ANYONE holding the log's public
 * key can verify it — the log is genuinely public-verifiable, not
 * HMAC-verifiable-only-by-the-owner. The keypair is generated per log
 * instance unless one is supplied; the MCP server persists its keypair to
 * ~/.chamber/transparency-log-key.json so the log survives restarts.
 *
 * DEFAULT OFF: plain chamberSeal/chamberOpen are untouched. Verification
 * only happens through sealWithTransparency / openWithTransparency /
 * VerifiedReadLayer (enabled: false by default). Enabling the mode without
 * a log, or with a log that has no entry for the content, refuses reads —
 * there is no silent downgrade to unverified reads.
 */

import {
  createHash,
  generateKeyPairSync,
  sign as edSign,
  verify as edVerify,
  type KeyObject,
} from "node:crypto";
import { chamberOpen, chamberSeal, type SealedBlob } from "./chamber.js";

export type TreeHead = {
  root: string; // hex, Merkle root over all leaves
  size: number; // leaf count
  timestamp: string; // ISO, when this head was signed
};

export type InclusionPromise = {
  leafIndex: number;
  leafHash: string; // hex, SHA-256 of the plaintext
  treeHead: TreeHead;
  treeHeadSig: string; // hex, Ed25519 signature over canonical tree head
};

export type InclusionProof = {
  leafIndex: number;
  leafHash: string; // hex
  path: { hash: string; isLeft: boolean }[]; // sibling hashes, leaf → root
  treeHead: TreeHead;
  treeHeadSig: string;
};

function leafHashOf(contentHash: Buffer): Buffer {
  return createHash("sha256")
    .update(Buffer.concat([Buffer.from([0x00]), contentHash]))
    .digest();
}

function nodeHash(left: Buffer, right: Buffer): Buffer {
  return createHash("sha256")
    .update(Buffer.concat([Buffer.from([0x01]), left, right]))
    .digest();
}

function canonicalTreeHead(head: TreeHead): string {
  return JSON.stringify({
    root: head.root,
    size: head.size,
    timestamp: head.timestamp,
  });
}

function computeLevels(leafHashes: Buffer[]): Buffer[][] {
  const levels: Buffer[][] = [leafHashes];
  let level = leafHashes;
  while (level.length > 1) {
    const next: Buffer[] = [];
    for (let i = 0; i < level.length; i += 2) {
      if (i + 1 < level.length) next.push(nodeHash(level[i], level[i + 1]));
      else next.push(level[i]); // odd node promoted unchanged
    }
    levels.push(next);
    level = next;
  }
  return levels;
}

/** Append-only Merkle transparency log. */
export class TransparencyLog {
  private leaves: Buffer[] = []; // content hashes (raw SHA-256 digests)
  private readonly signingKey: KeyObject;
  private readonly verifyKey: KeyObject;
  // Append-only cache: tree levels are rebuilt only when the leaf count
  // changes, so a verified read is O(log n) hash ops, not O(n). Without
  // this, every read rehashed the whole log (measured 88ms at 1024 leaves).
  private levelsCache: { size: number; levels: Buffer[][] } | null = null;

  private getLevels(): Buffer[][] {
    if (!this.levelsCache || this.levelsCache.size !== this.leaves.length) {
      this.levelsCache = {
        size: this.leaves.length,
        levels: computeLevels(this.leaves.map(leafHashOf)),
      };
    }
    return this.levelsCache.levels;
  }

  constructor(keypair?: { privateKey: KeyObject; publicKey: KeyObject }) {
    if (keypair) {
      this.signingKey = keypair.privateKey;
      this.verifyKey = keypair.publicKey;
    } else {
      const { privateKey, publicKey } = generateKeyPairSync("ed25519");
      this.signingKey = privateKey;
      this.verifyKey = publicKey;
    }
  }

  /** Public key (JWK) — anyone holding this verifies tree heads. */
  get publicKeyJwk(): JsonWebKey {
    return this.verifyKey.export({ format: "jwk" });
  }

  /** Private key (JWK) — persist this alongside the log, never share it. */
  get privateKeyJwk(): JsonWebKey {
    return this.signingKey.export({ format: "jwk" });
  }

  get size(): number {
    return this.leaves.length;
  }

  /** Append a content hash; returns the signed inclusion promise. */
  append(contentHashHex: string): InclusionPromise {
    const hash = Buffer.from(contentHashHex, "hex");
    if (hash.length !== 32) {
      throw new Error("content hash must be 32 bytes (SHA-256 hex)");
    }
    this.leaves.push(hash);
    const head = this.currentTreeHead();
    return {
      leafIndex: this.leaves.length - 1,
      leafHash: contentHashHex,
      treeHead: head,
      treeHeadSig: this.signTreeHead(head),
    };
  }

  /** Current signed tree head. */
  currentTreeHead(): TreeHead {
    const levels = this.getLevels();
    const root =
      levels.length === 0 || levels[0].length === 0
        ? createHash("sha256").update(Buffer.alloc(0)).digest()
        : levels.at(-1)![0];
    return {
      root: root.toString("hex"),
      size: this.leaves.length,
      timestamp: new Date().toISOString(),
    };
  }

  signTreeHead(head: TreeHead): string {
    return edSign(null, Buffer.from(canonicalTreeHead(head), "utf8"), this.signingKey).toString("hex");
  }

  verifyTreeHead(head: TreeHead, sigHex: string): boolean {
    try {
      return edVerify(
        null,
        Buffer.from(canonicalTreeHead(head), "utf8"),
        this.verifyKey,
        Buffer.from(sigHex, "hex")
      );
    } catch {
      return false;
    }
  }

  /** Index of a content hash in the log, or -1 when absent. */
  findLeaf(contentHashHex: string): number {
    const target = Buffer.from(contentHashHex, "hex");
    return this.leaves.findIndex((l) => l.equals(target));
  }

  /** Inclusion proof for a leaf index against the CURRENT tree head. */
  inclusionProof(leafIndex: number): InclusionProof {
    if (leafIndex < 0 || leafIndex >= this.leaves.length) {
      throw new Error(`leaf index out of range: ${leafIndex}`);
    }
    const levels = this.getLevels();
    const path: { hash: string; isLeft: boolean }[] = [];
    let idx = leafIndex;
    for (let depth = 0; depth < levels.length - 1; depth++) {
      const level = levels[depth];
      const isRight = idx % 2 === 1;
      const siblingIdx = isRight ? idx - 1 : idx + 1;
      if (siblingIdx < level.length) {
        path.push({ hash: level[siblingIdx].toString("hex"), isLeft: isRight });
      }
      // else: odd node promoted, no sibling at this level
      idx = Math.floor(idx / 2);
    }
    const head = this.currentTreeHead();
    return {
      leafIndex,
      leafHash: this.leaves[leafIndex].toString("hex"),
      path,
      treeHead: head,
      treeHeadSig: this.signTreeHead(head),
    };
  }

  /**
   * Verify an inclusion proof against its tree head. Checks the signature
   * AND the Merkle path. Either failure = false (read refused by caller).
   */
  verifyInclusion(proof: InclusionProof): boolean {
    if (!this.verifyTreeHead(proof.treeHead, proof.treeHeadSig)) return false;
    if (proof.treeHead.size !== this.leaves.length) return false;
    let cur = leafHashOf(Buffer.from(proof.leafHash, "hex"));
    let idx = proof.leafIndex;
    for (const step of proof.path) {
      const sib = Buffer.from(step.hash, "hex");
      cur = step.isLeft ? nodeHash(sib, cur) : nodeHash(cur, sib);
      idx = Math.floor(idx / 2);
    }
    void idx;
    return cur.toString("hex") === proof.treeHead.root;
  }

  /** Serialize leaves for persistence (hex array). */
  serializeLeaves(): string[] {
    return this.leaves.map((l) => l.toString("hex"));
  }

  /** Restore leaves from persistence. The log is append-only: restore only ever grows it. */
  restoreLeaves(hashesHex: string[]): void {
    for (const h of hashesHex) {
      const b = Buffer.from(h, "hex");
      if (b.length === 32) this.leaves.push(b);
    }
  }
}

export function contentHash(plaintext: Buffer): string {
  return createHash("sha256").update(plaintext).digest("hex");
}

export type TransparentSealResult = {
  sealed: SealedBlob;
  secondShare: string;
  contentHash: string;
  inclusionPromise: InclusionPromise;
};

/**
 * Seal + append the content hash to the log. The inclusion promise is the
 * write-time receipt that the content is in the log.
 */
export function sealWithTransparency(
  plaintext: Buffer,
  log: TransparencyLog
): TransparentSealResult {
  const { sealed, secondShare } = chamberSeal(plaintext);
  const hash = contentHash(plaintext);
  const inclusionPromise = log.append(hash);
  return { sealed, secondShare, contentHash: hash, inclusionPromise };
}

/**
 * Verified read: open the blob, recompute the content hash, and require an
 * inclusion proof against the log's signed tree head. Absent hash or a
 * proof/signature that does not verify = read REFUSED (throw). Never serves
 * data that fails verification.
 */
export function openWithTransparency(
  sealed: SealedBlob,
  secondShare: string,
  log: TransparencyLog
): Buffer {
  const plaintext = chamberOpen(sealed, secondShare);
  const hash = contentHash(plaintext);
  const leafIndex = log.findLeaf(hash);
  if (leafIndex < 0) {
    throw new Error(
      "transparency log: content hash absent from the log — read refused"
    );
  }
  const proof = log.inclusionProof(leafIndex);
  if (!log.verifyInclusion(proof)) {
    throw new Error(
      "transparency log: inclusion proof failed against the signed tree head — read refused (forked or tampered log)"
    );
  }
  return plaintext;
}

/**
 * The read layer with the mode flag. Default OFF: plain chamberOpen, no log
 * consulted. When enabled, every open goes through openWithTransparency
 * and every seal appends via sealWithTransparency. There is no silent
 * downgrade: enabled + missing log entry = refused read.
 */
export class VerifiedReadLayer {
  private log: TransparencyLog | null;
  enabled: boolean;

  constructor(log: TransparencyLog | null = null, enabled = false) {
    this.log = log;
    this.enabled = enabled;
  }

  setLog(log: TransparencyLog | null): void {
    this.log = log;
  }

  seal(plaintext: Buffer): TransparentSealResult | { sealed: SealedBlob; secondShare: string } {
    if (this.enabled) {
      if (!this.log) throw new Error("transparency mode enabled but no log configured — seal refused");
      return sealWithTransparency(plaintext, this.log);
    }
    return chamberSeal(plaintext);
  }

  open(sealed: SealedBlob, secondShare: string): Buffer {
    if (this.enabled) {
      if (!this.log) throw new Error("transparency mode enabled but no log configured — read refused");
      return openWithTransparency(sealed, secondShare, this.log);
    }
    return chamberOpen(sealed, secondShare);
  }
}
