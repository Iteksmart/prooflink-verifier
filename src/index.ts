// Legacy pre-v3 verifier (verifies the historical ProofLinkReceipt shape:
// receipt_id / sha256 / previous_hash / before_state / nist_controls …).
// See the DRIFT NOTICE in ./standard-v3 — the LIVE ledger emits v3 receipts.
export * from './prooflink-verifier';

// ProofLink Receipt Standard v3.0 — conformant verifier for LIVE v3 receipts.
// Spec: https://verify.itechsmart.dev/api/how-to-verify
export {
  verifyReceiptV3,
  verifyV3,
  verifyChainV3,
  canonicalize as canonicalizeV3,
  importEd25519PublicKey,
  PUBLISHED_PUBLIC_KEY,
} from './standard-v3';
export type { V3Receipt, V3Signature, V3Check, V3Result } from './standard-v3';

// Live-ledger helpers: fetch + verify against verify.itechsmart.dev, and
// pointer-linkage verification for the public summary list (/api/receipts).
export {
  fetchAndVerifyReceipt,
  fetchAndVerifyChain,
  verifyPublicChain,
  DEFAULT_LEDGER,
} from './live';
export type { PublicChainReceipt, PublicChainResult } from './live';
