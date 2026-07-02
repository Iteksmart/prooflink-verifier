/**
 * ProofLink Receipt Standard v3.0 — conformant v3 verifier.
 *
 * Spec: https://github.com/Iteksmart/prooflink-standard/blob/main/ProofLink-Receipt-Standard-v3.md
 * Live: https://verify.itechsmart.dev/api/how-to-verify
 *
 * ─────────────────────────────────────────────────────────────────────────
 * DRIFT NOTICE
 * The original exports in `prooflink-verifier.ts` (computeReceiptHash,
 * verifyReceipt, verifyChain over the `ProofLinkReceipt` shape with fields
 * receipt_id / sha256 / previous_hash / before_state / nist_controls …) verify
 * a PRE-v3 receipt shape that the LIVE ledger no longer emits. Live v3 receipts
 * use id / hash_sha256 / prev_hash / canonical_bytes / signature, are Ed25519
 * signed, and hash the FULL canonicalized payload (not a fixed field list).
 * This module is the Standard-v3.0-conformant verifier for live v3 receipts.
 * The legacy exports are retained unchanged for historical/pre-v3 receipts.
 * ─────────────────────────────────────────────────────────────────────────
 *
 * Zero third-party dependencies (Node 18+ built-in `crypto`).
 * Reproduces the canonical live verification exactly:
 *   1. hash integrity        SHA256(canonical_bytes) == hash_sha256
 *   2. canonical re-derive    json.dumps(payload, sort_keys, separators=(",",":"),
 *                             ensure_ascii=False) == canonical_bytes
 *   3. Ed25519 signature      sig over raw canonical_bytes under embedded pubkey
 *   4. chain link             prev_hash == previous entry's hash_sha256
 */

import { createHash, createPublicKey, verify as edVerify, KeyObject } from "node:crypto";

export const PUBLISHED_PUBLIC_KEY =
  "21102eaa68ea9ed42c05a2253aa953d33c59b5348ff8659018146e59fb061b97";

export interface V3Signature {
  algorithm: string;
  public_key: string;
  value: string;
  signs?: string;
}

export interface V3Receipt {
  id: string;
  timestamp: string;
  category: string;
  subject: string;
  action: string;
  actor: string;
  outcome: string;
  schema_version: string;
  prev_hash: string;
  chain_position: number;
  canonical_bytes: string;
  hash_sha256: string;
  signature: V3Signature;
  compliance_tags?: string[];
  supersedes?: string;
  learned_from?: string[];
  [k: string]: unknown;
}

export interface V3Check {
  name: string;
  passed: boolean;
  detail: string;
}

export interface V3Result {
  valid: boolean;
  id: string;
  checks: V3Check[];
  errors: string[];
}

const COMPUTED = ["canonical_bytes", "signature", "hash_sha256"];

/** Canonical JSON bytes byte-for-byte identical to Python's
 *  json.dumps(x, sort_keys=True, separators=(",",":"), ensure_ascii=False). */
export function canonicalize(value: unknown): Buffer {
  return Buffer.from(canon(value), "utf-8");
}
function canon(v: unknown): string {
  if (v === null || typeof v !== "object") return JSON.stringify(v);
  if (Array.isArray(v)) return "[" + v.map(canon).join(",") + "]";
  const o = v as Record<string, unknown>;
  const parts: string[] = [];
  for (const k of Object.keys(o).sort()) {
    if (o[k] === undefined) continue;
    parts.push(JSON.stringify(k) + ":" + canon(o[k]));
  }
  return "{" + parts.join(",") + "}";
}

const SPKI = Buffer.from("302a300506032b6570032100", "hex");
export function importEd25519PublicKey(hex: string): KeyObject {
  return createPublicKey({
    key: Buffer.concat([SPKI, Buffer.from(hex, "hex")]),
    format: "der",
    type: "spki",
  });
}

/** Verify one v3 receipt against Standard v3.0. Never throws on a failed check. */
export function verifyReceiptV3(receipt: V3Receipt, prevHash?: string): V3Result {
  const checks: V3Check[] = [];
  const errors: string[] = [];
  const id = receipt?.id ?? "<no-id>";

  if (String(receipt?.schema_version) !== "3.0") {
    errors.push(`schema_version is ${JSON.stringify(receipt?.schema_version)}; Standard v3.0 covers "3.0"`);
    return { valid: false, id, checks, errors };
  }

  let canonBytes: Buffer;
  try {
    canonBytes = Buffer.from(receipt.canonical_bytes, "hex");
  } catch (e) {
    checks.push({ name: "hash_integrity", passed: false, detail: `canonical_bytes not hex: ${e}` });
    return { valid: false, id, checks, errors };
  }

  // 1. hash integrity
  const got = createHash("sha256").update(canonBytes).digest("hex");
  const h1 = got === receipt.hash_sha256;
  checks.push({ name: "hash_integrity", passed: h1,
    detail: h1 ? "SHA256(canonical_bytes) == hash_sha256"
               : `hash mismatch: ${got.slice(0, 16)}… vs ${String(receipt.hash_sha256).slice(0, 16)}…` });

  // 2. canonical re-derivation
  const payload: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(receipt)) if (!COMPUTED.includes(k)) payload[k] = v;
  const rederived = canonicalize(payload);
  const h2 = rederived.equals(canonBytes);
  checks.push({ name: "canonical_rederivation", passed: h2,
    detail: h2 ? "re-derived canonical bytes match" : "canonical re-derivation MISMATCH — signed field tampered" });

  // 3. Ed25519 signature
  const sig = receipt.signature;
  if (!sig || !sig.public_key || !sig.value) {
    checks.push({ name: "ed25519_signature", passed: false, detail: "signature missing/malformed" });
  } else {
    try {
      const ok = edVerify(null, canonBytes, importEd25519PublicKey(sig.public_key), Buffer.from(sig.value, "hex"));
      checks.push({ name: "ed25519_signature", passed: ok,
        detail: ok ? `Ed25519 OK (key ${sig.public_key.slice(0, 16)}…)` : "Ed25519 signature INVALID" });
    } catch (e) {
      checks.push({ name: "ed25519_signature", passed: false, detail: `signature error: ${e}` });
    }
  }

  // 4. chain link
  if (prevHash !== undefined) {
    const h4 = receipt.prev_hash === prevHash;
    checks.push({ name: "chain_link", passed: h4,
      detail: h4 ? "prev_hash links to previous entry"
                 : `chain BROKEN: ${String(receipt.prev_hash).slice(0, 16)}… != ${prevHash.slice(0, 16)}…` });
  }

  const valid = checks.every((c) => c.passed) && errors.length === 0;
  return { valid, id, checks, errors };
}

/** Boolean convenience wrapper. */
export function verifyV3(receipt: V3Receipt, prevHash?: string): boolean {
  return verifyReceiptV3(receipt, prevHash).valid;
}

/** Verify an oldest-first chain (e.g. /api/export order) of v3 receipts. */
export function verifyChainV3(receipts: V3Receipt[]): { chain_valid: boolean; results: V3Result[] } {
  const results = receipts.map((r, i) => verifyReceiptV3(r, i > 0 ? receipts[i - 1].hash_sha256 : undefined));
  return { chain_valid: results.every((r) => r.valid), results };
}
