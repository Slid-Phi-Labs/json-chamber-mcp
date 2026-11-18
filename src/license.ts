/**
 * Cloak license for json-chamber-mcp.
 * 24h try, then $9/mo · $99/yr. Open does not call this module.
 *
 * Purchase comes ONLY from a signed license.json (purchased:true, HMAC
 * under the Chamber master secret). There is no key-substring unlock:
 * no environment value, API key, or key shape grants a purchase.
 *
 * There is no default master secret. Without CHAMBER_MASTER_SECRET
 * (or JSON_CHAMBER_MASTER / TRU8_MASTER_SECRET) the gate fails closed:
 * cloak stays off and no license file is written. The walkthrough sets
 * the secret explicitly via env; nothing in this module invents one.
 *
 * KILLED is recoverable, not permanent: a valid signed purchased license
 * revives/overrides it automatically, and manual recovery (delete
 * ~/.chamber/KILLED) is documented in the README ("License recovery").
 * ~/.chamber is mode 0700 and license files are mode 0600.
 */

import {
  createHmac,
  createHash,
  timingSafeEqual,
} from "node:crypto";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

const LICENSE_DIR = join(homedir(), ".chamber");
const LICENSE_FILE = join(LICENSE_DIR, "license.json");
const KILL_FILE = join(LICENSE_DIR, "KILLED");

export const EVAL_SECONDS = 86400;
export const PRICE_USD = 99;
export const PURCHASE_URL =
  process.env.CHAMBER_PURCHASE_URL ?? "https://www.slidphilabs.com/chamber";

function masterBytes(): Buffer {
  const raw =
    process.env.CHAMBER_MASTER_SECRET ||
    process.env.JSON_CHAMBER_MASTER ||
    process.env.TRU8_MASTER_SECRET;
  if (!raw) {
    // Fail closed: never fall back to a shipped demo secret. Anyone who
    // can read the repo could mint licenses with a hardcoded secret.
    throw new Error(
      "no Chamber master secret configured — set CHAMBER_MASTER_SECRET " +
        "(or JSON_CHAMBER_MASTER / TRU8_MASTER_SECRET); cloak stays off until then"
    );
  }
  const b = Buffer.from(raw, "utf8");
  return b.length >= 32 ? b : createHash("sha256").update(b).digest();
}

function sign(payload: object): string {
  const msg = JSON.stringify(payload, Object.keys(payload as object).sort());
  return createHmac("sha256", masterBytes()).update(msg).digest("hex");
}

function ensureDir(): void {
  if (!existsSync(LICENSE_DIR)) {
    mkdirSync(LICENSE_DIR, { recursive: true, mode: 0o700 });
  }
  try {
    chmodSync(LICENSE_DIR, 0o700);
  } catch {
    // Best effort: a read-only parent or odd FS must not break the gate.
  }
}

/** Write a license-dir file readable only by its owner. */
function writePrivate(path: string, data: string): void {
  writeFileSync(path, data, { mode: 0o600 });
  try {
    chmodSync(path, 0o600);
  } catch {
    // Best effort (see ensureDir).
  }
}

export type LicenseStatus = {
  alive: boolean;
  status: "eval" | "purchased" | "dead";
  reason?: string;
  remaining_sec?: number;
  remaining_hours?: number;
  price?: number;
  purchase_url?: string;
  expires_at?: string;
};

function dead(reason: string): LicenseStatus {
  return {
    alive: false,
    status: "dead",
    reason,
    price: PRICE_USD,
    purchase_url: PURCHASE_URL,
  };
}

export class LicenseManager {
  /**
   * Load and verify the stored license. Returns null when no license
   * file exists yet. Throws on a signature mismatch (and writes KILLED)
   * or when no master secret is configured (fail closed, no KILLED).
   */
  private loadVerified(): Record<string, unknown> | null {
    ensureDir();
    if (!existsSync(LICENSE_FILE)) return null;
    const raw = JSON.parse(readFileSync(LICENSE_FILE, "utf8"));
    const { sig, ...data } = raw;
    const expected = sign(data);
    if (
      typeof sig !== "string" ||
      sig.length !== expected.length ||
      !timingSafeEqual(Buffer.from(sig), Buffer.from(expected))
    ) {
      writePrivate(KILL_FILE, "tamper-sig");
      throw new Error("license signature mismatch – killed");
    }
    try {
      chmodSync(LICENSE_FILE, 0o600);
    } catch {
      // Best effort (see ensureDir).
    }
    return data;
  }

  private createEval(): Record<string, unknown> {
    ensureDir();
    const now = Math.floor(Date.now() / 1000);
    const lic = {
      type: "eval",
      product: "json-chamber",
      first_run: now,
      eval_expires: now + EVAL_SECONDS,
      purchased: false,
      device_hash: createHash("sha256")
        .update(homedir())
        .digest("hex")
        .slice(0, 16),
    };
    const signed = { ...lic, sig: sign(lic) };
    writePrivate(LICENSE_FILE, JSON.stringify(signed, null, 2));
    return lic;
  }

  check(): LicenseStatus {
    let lic: Record<string, unknown> | null;
    try {
      lic = this.loadVerified();
    } catch (e) {
      return dead(e instanceof Error ? e.message : String(e));
    }

    // Purchase BEFORE kill: a valid signed purchased license revives
    // and overrides a KILLED marker (e.g. a trial that expired before
    // the purchase landed). Revival clears the marker.
    if (lic && lic.purchased === true) {
      if (existsSync(KILL_FILE)) {
        try {
          rmSync(KILL_FILE);
        } catch {
          // Best effort: the purchase still grants access this run.
        }
      }
      return {
        alive: true,
        status: "purchased",
        price: PRICE_USD,
        purchase_url: PURCHASE_URL,
      };
    }

    if (existsSync(KILL_FILE)) {
      return dead(
        "Chamber hard-killed (KILLED marker present). A signed purchased " +
          "license revives it automatically; otherwise delete " +
          "~/.chamber/KILLED to recover — see README 'License recovery'."
      );
    }

    if (!lic) {
      try {
        lic = this.createEval();
      } catch (e) {
        // No master secret (or unwritable dir): fail closed, no KILLED.
        return dead(e instanceof Error ? e.message : String(e));
      }
    }

    const now = Math.floor(Date.now() / 1000);
    const expires = Number(lic.eval_expires ?? 0);
    if (now > expires) {
      writePrivate(KILL_FILE, "expired");
      return dead(
        `Chamber cloak try ended. Seal is off until a cloak license is live ($9/mo · $99/yr). Open of already-sealed blobs is keys-only. ${PURCHASE_URL}`
      );
    }
    const remaining = Math.max(0, expires - now);
    return {
      alive: true,
      status: "eval",
      remaining_sec: remaining,
      remaining_hours: Math.round((remaining / 3600) * 10) / 10,
      expires_at: new Date(expires * 1000).toISOString(),
      price: PRICE_USD,
      purchase_url: PURCHASE_URL,
    };
  }

  requireAlive(): void {
    const s = this.check();
    if (!s.alive) {
      throw new Error(
        [
          "╔══════════════════════════════════════════════════════╗",
          "║  CHAMBER CLOAK LICENSE OFF                           ║",
          `║  ${s.reason ?? "Cloak license expired"}`,
          `║  $9/mo · $99/yr → ${PURCHASE_URL}`,
          "║  Open of sealed blobs still works with both keys.    ║",
          "╚══════════════════════════════════════════════════════╝",
        ].join("\n")
      );
    }
  }
}
