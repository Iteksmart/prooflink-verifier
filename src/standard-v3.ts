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
  signer_trusted?: boolean;
  signature_valid?: boolean;
  bitcoin_verified?: false;
  verification_scope?: string;
}

export interface V3TrustOptions {
  trustedPublicKeys?: readonly string[];
  revokedPublicKeys?: readonly string[];
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
  if (typeof hex !== 'string' || !/^[0-9a-f]{64}$/i.test(hex)) throw new Error('Invalid Ed25519 public key encoding');
  return createPublicKey({
    key: Buffer.concat([SPKI, Buffer.from(hex, "hex")]),
    format: "der",
    type: "spki",
  });
}

/** Verify one v3 receipt against Standard v3.0. Never throws on a failed check. */
export function verifyReceiptV3(receipt: V3Receipt, prevHash?: string, options: V3TrustOptions = {}): V3Result {
  const checks: V3Check[] = [];
  const errors: string[] = [];
  const id = receipt?.id ?? "<no-id>";
  if (!receipt || typeof receipt !== 'object' || Array.isArray(receipt)) return { valid: false, id, checks, errors: ['receipt must be an object'], bitcoin_verified: false };
  let trusted: string[] = [], revoked: string[] = [];
  try {
    const parseKeys = (keys: readonly string[]) => {
      if (!Array.isArray(keys) || keys.some(k => typeof k !== 'string' || !/^[0-9a-f]{64}$/i.test(k))) throw new Error('Invalid trusted/revoked key policy');
      return keys.map(k => k.toLowerCase());
    };
    trusted = parseKeys(options.trustedPublicKeys === undefined ? [PUBLISHED_PUBLIC_KEY] : options.trustedPublicKeys);
    revoked = parseKeys(options.revokedPublicKeys === undefined ? [] : options.revokedPublicKeys);
  } catch (error) { return { valid: false, id, checks, errors: [(error as Error).message], bitcoin_verified: false }; }

  const schema = String(receipt?.schema_version);
  const v3 = schema === "3.0";
  // v2.0 receipts sealed with the same crypto (canonical_bytes + Ed25519 over
  // them) are signature-verifiable; only hash recompute + canonical re-derivation
  // are v3-normative (a v2 hash_sha256 is a pre-chain ledger-internal link).
  const v2crypto = schema === "2.0" && !!receipt.canonical_bytes && !!receipt.signature;
  if (!v3 && !v2crypto) {
    errors.push(`schema_version is ${JSON.stringify(receipt?.schema_version)}; covers "3.0" (and crypto-bearing "2.0")`);
    return { valid: false, id, checks, errors };
  }

  let canonBytes: Buffer;
  try {
    if (typeof receipt.canonical_bytes !== 'string' || !/^(?:[0-9a-f]{2})+$/i.test(receipt.canonical_bytes)) throw new Error('Invalid canonical hexadecimal bytes');
    canonBytes = Buffer.from(receipt.canonical_bytes, "hex");
  } catch (e) {
    checks.push({ name: "hash_integrity", passed: false, detail: `canonical_bytes not hex: ${e}` });
    return { valid: false, id, checks, errors };
  }

  if (v3) {
    // 1. hash integrity
    const got = createHash("sha256").update(canonBytes).digest("hex");
    const h1 = got === receipt.hash_sha256;
    checks.push({ name: "hash_integrity", passed: h1,
      detail: h1 ? "SHA256(canonical_bytes) == hash_sha256"
                 : `hash mismatch: ${got.slice(0, 16)}… vs ${String(receipt.hash_sha256).slice(0, 16)}…` });

    // 2. canonical re-derivation
    const payload: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(receipt)) if (!COMPUTED.includes(k)) payload[k] = v;
    try {
      const rederived = canonicalize(payload);
      const h2 = rederived.equals(canonBytes);
      checks.push({ name: "canonical_rederivation", passed: h2,
        detail: h2 ? "re-derived canonical bytes match" : "canonical re-derivation MISMATCH — signed field tampered" });
    } catch (error) {
      checks.push({ name: 'canonical_rederivation', passed: false, detail: `Unsupported canonical payload: ${(error as Error).message}` });
    }
  } else {
    // v2: bind via signed-payload consistency (hash/canonical not recomputable).
    try {
      const signed = JSON.parse(canonBytes.toString("utf-8")) as Record<string, unknown>;
      const core = ["category", "actor", "subject", "action", "outcome", "timestamp"];
      const mism = core.filter((k) => k in signed && (receipt as Record<string, unknown>)[k] !== undefined
                                      && signed[k] !== (receipt as Record<string, unknown>)[k]);
      checks.push({ name: "payload_consistency", passed: mism.length === 0,
        detail: mism.length === 0 ? "displayed core fields match the signed canonical payload"
                                  : `signed-payload mismatch on: ${mism.join(", ")}` });
    } catch (e) {
      checks.push({ name: "payload_consistency", passed: false, detail: `canonical_bytes not JSON: ${e}` });
    }
  }

  // 3. Ed25519 signature
  const sig = receipt.signature;
  const signer = typeof sig?.public_key === 'string' ? sig.public_key.toLowerCase() : '';
  const signerTrusted = /^[0-9a-f]{64}$/.test(signer) && trusted.includes(signer) && !revoked.includes(signer);
  checks.push({ name: 'signer_trust', passed: signerTrusted, detail: signerTrusted ? 'signer matches a configured trusted, non-revoked key' : 'signer is missing, malformed, untrusted or revoked' });
  if (!sig || !sig.public_key || !sig.value) {
    checks.push({ name: "ed25519_signature", passed: false, detail: "signature missing/malformed" });
  } else {
    try {
      if (sig.algorithm !== 'Ed25519') throw new Error('Unsupported signature algorithm');
      const metadata = sig as unknown as Record<string, unknown>;
      for (const field of ['signs','signed_payload']) if (field in metadata && metadata[field] !== 'canonical_bytes') throw new Error('Signature must cover canonical_bytes');
      if (typeof sig.value !== 'string' || !/^[0-9a-f]{128}$/i.test(sig.value)) throw new Error('Invalid signature encoding');
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
  return { valid, id, checks, errors, signer_trusted: signerTrusted,
    signature_valid: checks.some(c => c.name === 'ed25519_signature' && c.passed), bitcoin_verified: false,
    verification_scope: 'receipt integrity and configured signer trust; Bitcoin and ledger inclusion not assessed' };
}

/** Boolean convenience wrapper. */
export function verifyV3(receipt: V3Receipt, prevHash?: string, options: V3TrustOptions = {}): boolean {
  return verifyReceiptV3(receipt, prevHash, options).valid;
}

/** Verify an oldest-first chain (e.g. /api/export order) of v3 receipts. */
export function verifyChainV3(receipts: V3Receipt[], options: V3TrustOptions = {}): { chain_valid: boolean; results: V3Result[] } {
  const results = receipts.map((r, i) => verifyReceiptV3(r, i > 0 ? receipts[i - 1].hash_sha256 : undefined, options));
  return { chain_valid: results.length > 0 && results.every((r) => r.valid), results };
}
