# ProofLink™ Verifier

**Open-source cryptographic verification logic for iTechSmart UAIO receipts.**

> Don't trust our AI. Trust the math.

---

## What is this?

When iTechSmart's UAIO platform autonomously remediates infrastructure — restarting a crashed pod, patching a misconfiguration, rolling back a bad deployment — it generates a **ProofLink receipt**: a cryptographically signed, hash-chained record of exactly what happened, when, and why.

This repository contains the **open-source verification logic** that anyone can use to independently confirm those receipts haven't been tampered with.

You don't need to trust us. You can verify the math yourself.

---

## How it works

Each ProofLink receipt contains:

1. **SHA-256 hash** — computed over all fields of the receipt (deterministic, canonical JSON)
2. **Previous hash** — the SHA-256 of the preceding receipt, creating a tamper-evident chain
3. **Chain position** — sequential integer; gaps indicate missing receipts
4. **Timestamp** — ISO 8601, must be chronologically ordered

Altering **any** receipt in the chain invalidates **every subsequent receipt** — the same principle as Bitcoin's blockchain, applied to infrastructure audit trails.

```
Receipt 0 (genesis)           Receipt 1                    Receipt 2
┌─────────────────────┐       ┌─────────────────────┐      ┌─────────────────────┐
│ sha256: abc123...   │──────▶│ prev_hash: abc123... │─────▶│ prev_hash: def456...│
│ prev_hash: null     │       │ sha256: def456...    │      │ sha256: ghi789...   │
│ chain_position: 0   │       │ chain_position: 1    │      │ chain_position: 2   │
└─────────────────────┘       └─────────────────────┘      └─────────────────────┘
```

If you alter Receipt 1's `action` field:
- Its computed SHA-256 changes → `sha256` field no longer matches → **tamper detected**
- Receipt 2's `prev_hash` no longer matches → **chain broken**

---

## Installation

```bash
npm install @iteksmart/prooflink-verifier
```

Or clone and use directly:

```bash
git clone https://github.com/Iteksmart/prooflink-verifier
cd prooflink-verifier
npm install
```

---

## Usage

### Verify a single receipt

```typescript
import { verifyReceipt } from '@iteksmart/prooflink-verifier'

const result = verifyReceipt(receipt, previousReceipt)

console.log(result.valid)           // true/false
console.log(result.tamper_detected) // true if hash or chain broken
console.log(result.checks)          // detailed check results
console.log(result.errors)          // list of failures
```

### Verify an entire chain

```typescript
import { verifyChain } from '@iteksmart/prooflink-verifier'

const receipts = await fetchReceiptsFromLedger()
const result = verifyChain(receipts)

console.log(result.chain_valid)      // true if all receipts intact
console.log(result.tamper_detected)  // true if any tampering found
console.log(result.tamper_position)  // which position was altered
console.log(result.summary)          // human-readable summary
```

### Compute a hash yourself

```typescript
import { computeReceiptHash } from '@iteksmart/prooflink-verifier'

const { sha256, ...receiptWithoutHash } = receipt
const computed = computeReceiptHash(receiptWithoutHash)

console.log(computed === receipt.sha256) // true if untampered
```

---

## The canonical hash function

The hash is computed over a deterministic JSON serialization of all fields **except** `sha256` itself:

```typescript
export function computeReceiptHash(receipt: Omit<ProofLinkReceipt, 'sha256'>): string {
  const canonical = JSON.stringify({
    receipt_id: receipt.receipt_id,
    version: receipt.version,
    timestamp: receipt.timestamp,
    container: receipt.container,
    executor: receipt.executor,
    trigger: receipt.trigger,
    action: receipt.action,
    action_parameters: receipt.action_parameters,
    before_state: receipt.before_state,
    after_state: receipt.after_state,
    nist_controls: receipt.nist_controls,
    human_input: receipt.human_input,
    arbiter_policy: receipt.arbiter_policy,
    previous_hash: receipt.previous_hash,
    chain_position: receipt.chain_position,
  }, null, 0)

  return crypto.createHash('sha256').update(canonical, 'utf8').digest('hex')
}
```

The field ordering is fixed and documented. You can reimplement this in any language and verify receipts independently.

---

## Verification checks

For each receipt, the verifier runs 5 checks:

| Check | What it verifies |
|-------|-----------------|
| `schema_valid` | All required fields present |
| `receipt_integrity` | Stored SHA-256 matches recomputed hash |
| `chain_link` | `previous_hash` matches prior receipt's `sha256` |
| `chain_position` | Position is sequential (no gaps) |
| `timestamp_order` | Timestamps are chronologically ordered |

---

## Live receipts

Verify real receipts from iTechSmart's production ledger:

```
https://verify.itechsmart.dev
https://api.itechsmart.dev/api/v1/prooflink/receipts
```

---

## Try the sandbox

See UAIO detect, fix, and prove a live Kubernetes OOMKilled crash:

```
https://itechsmart.dev/break-it
```

---

## Contributing

This verifier is intentionally minimal. The goal is auditable simplicity — not feature bloat.

PRs welcome for:
- Additional language implementations (Python, Go, Rust)
- OpenTimestamps proof verification
- CLI tool
- Test vectors

---

## License

MIT — use freely, audit openly, verify everything.

---

## About iTechSmart

iTechSmart builds UAIO (Unified Autonomous IT Operations) — the first enterprise platform that autonomously detects, remediates, and cryptographically proves every infrastructure action.

- Website: [itechsmart.dev](https://itechsmart.dev)
- Verify receipts: [verify.itechsmart.dev](https://verify.itechsmart.dev)
- Whitepaper: [whitepaper.itechsmart.dev](https://whitepaper.itechsmart.dev)

SDVOSB · CAGE: 172W2 · NVIDIA Inception · NIST CSF 96/100
