# ProofLink™ Verifier

[![Verify Live](https://img.shields.io/badge/verify-live-00A870)](https://verify.itechsmart.dev)

> **Every other AI-accountability standard is a PDF. ProofLink is a running ledger of
> 79,000+ cryptographically-sealed AI actions you can verify right now — not a spec, a
> live chain.** → **[verify.itechsmart.dev](https://verify.itechsmart.dev)**

**Open-source, zero-dependency cryptographic verification logic for iTechSmart UAIO
receipts** — the reference implementation of the
[ProofLink Receipt Standard **v3.0**](https://github.com/Iteksmart/prooflink-standard/blob/main/ProofLink-Receipt-Standard-v3.md).

> Don't trust our AI. Trust the math.

## Not a spec — a running chain

Live snapshot (2026-07-02, `/api/chain` + `/api/stats`): **79,000+ receipts**, chain
**intact (`chain_intact: true`, 0 breaks)**, **2,100+ strict cryptographically-verifiable v3
receipts** (every new action is sealed as v3), **13,700+ Bitcoin-anchored** (~17%, growing
daily).

**Honest two-era note.** The `*V3` API below strictly verifies v3 receipts
(`schema_version "3.0"`): hash recompute + canonical re-derivation + Ed25519 + chain link.
Legacy v1/v2 receipts are pointer-linked and preserved unmodified — disclosed openly at
`/api/stats`. `strict_full_chain_linked: false` is the disclosed count of legacy pointer
links, **not a chain break** (`breaks: 0`). We do not claim all 79k are strict-verifiable;
2,100+ v3 are, and the count grows with every action.

## Built for the regulations

| Regulation / framework | ProofLink field / mechanism that satisfies it |
|---|---|
| **EU AI Act (Reg. 2024/1689) Article 12** — automatic tamper-evident logging for high-risk AI | Append-only hash chain; every action seals `timestamp`, `actor`, `action`, `subject`, `outcome`, `details` |
| **NIST AI RMF 1.0 — MEASURE 2.7 / MANAGE 4.1** — monitoring evaluated & documented | `security` / `platform_fix` / `platform_health_check` receipts, signed & immutable; `actor` separates system/agent/operator |
| **CMMC L2 — AU.L2-3.3.1 / AU.L2-3.3.8** — retain & protect audit logs | SHA-256 chain + Ed25519 make any edit/deletion/reorder detectable; Bitcoin anchoring adds external existence proof |
| **SOC 2 — CC7.2 / CC7.3 / CC8.1** — anomaly monitoring & change management | `signal_classified` / `security` receipts; `config_change` records `{before_hash, after_hash, diff_summary}` |
| **ISO/IEC 42001:2023 — Clause 9.1** — retain documented monitoring evidence | The receipt ledger is the retained cryptographic evidence; `compliance_tags` seal the control claim inside the signature |

## Connect anything — every call seals a receipt

- **MCP server** — verify/search receipts from any MCP client (Claude, Cursor, Copilot,
  LangGraph, CrewAI): `prooflink_verify_receipt`, `prooflink_search_receipts`,
  `prooflink_verify_chain`.
- **FastAPI / REST** — `verify.itechsmart.dev` exposes `/api/export`, `/api/verify/<id>`,
  `/api/chain`, `/api/stats`, `/api/anchors`, `/api/how-to-verify`.
- **SDK** — [`prooflink-sdk`](https://github.com/Iteksmart/prooflink-sdk) (Python +
  TypeScript) for sealing; this repo for zero-dependency verification.

ProofLink aligns conceptually with the IETF Internet-Draft
[`draft-sharif-agent-audit-trail-00`](https://datatracker.ietf.org/doc/html/draft-sharif-agent-audit-trail-00)
(same problem, shared SHA-256 hash-chain core) while differing deliberately on
canonicalization (`json.dumps`, not RFC 8785 JCS) and signature (Ed25519, not ECDSA P-256).

---

## Conformance to ProofLink Receipt Standard v3.0

This verifier ships a **Standard v3.0-conformant** verifier for the **live v3
receipt format** ([`ProofLink-Receipt-Standard-v3.md`](https://github.com/Iteksmart/prooflink-standard/blob/main/ProofLink-Receipt-Standard-v3.md)). Import the `*V3` API:

```ts
import { verifyV3, verifyReceiptV3, verifyChainV3 } from "prooflink-verifier";

const res = await fetch("https://verify.itechsmart.dev/api/verify/<id>");
const { receipt } = await res.json();
verifyV3(receipt);                 // boolean — all 4 Standard checks
verifyReceiptV3(receipt, prevHash) // { valid, checks[], errors[] }
```

It performs the four normative checks: (1) `SHA256(canonical_bytes) == hash_sha256`,
(2) canonical re-derivation of `canonical_bytes`, (3) Ed25519 signature over the raw
`canonical_bytes` under the embedded (published) public key, (4) `prev_hash` chain link.

### ⚠ Schema drift — read this

The **original** exports (`computeReceiptHash`, `verifyReceipt`, `verifyChain`,
`ProofLinkVerifier`) target a **pre-v3 / legacy receipt shape**
(`receipt_id`, `sha256`, `previous_hash`, `before_state`, `after_state`,
`nist_controls`, `arbiter_policy`, …) and hash a **fixed field list** with
`JSON.stringify` and **no signature**. **Live receipts no longer match that shape.**
The live ledger emits v3 receipts (`id`, `hash_sha256`, `prev_hash`,
`canonical_bytes`, Ed25519 `signature`, full-payload canonicalization). Use the
`*V3` API above for anything fetched from `verify.itechsmart.dev` today. The legacy
exports are retained unchanged for historical/pre-v3 receipts. See the DRIFT NOTICE
at the top of `src/standard-v3.ts`.

---


## Why Cryptographic Proof?

Modern enterprise IT generates millions of autonomous actions per day — auto-scaling, patching, remediating, classifying. Most happen with no human in the loop. The audit story today is a mess of mutable logs, ad-hoc PDFs, and dashboards no one trusts.

Regulators are catching up. **EU AI Act Article 12** (enforcement 2026-08-02) requires high-risk AI systems to maintain tamper-evident logs of every decision. NIST AI RMF and SOC 2 are tightening too.

A cryptographic receipt chain is the cheapest way to meet those requirements *and* the only way to prove autonomous behavior to a skeptical auditor. ProofLink generates one receipt per autonomous action, SHA-256 hashed, linked to the previous receipt, and publicly verifiable at [verify.itechsmart.dev](https://verify.itechsmart.dev).

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


## EU AI Act Article 12 Alignment

Article 12 of the EU AI Act (effective 2026-08-02) requires providers of high-risk AI systems to maintain automatic, tamper-evident logs of every decision. Mutable log files, post-hoc PDFs, and ephemeral dashboards do not satisfy this requirement.

ProofLink receipts satisfy Article 12 by design:

| Article 12 requirement | ProofLink mechanism |
|---|---|
| Automatic logging at runtime | Receipt generated synchronously on every autonomous action |
| Tamper-evident records | SHA-256 hash chain — altering any receipt invalidates every subsequent one |
| Identification of the system | `executor` field carries the model/agent identifier |
| Chronological ordering | `chain_position` integer + ISO 8601 `timestamp`, both verified during chain checks |
| Retention | Hash chain stored append-only; OpenTimestamps anchor optionally pins to Bitcoin |

## NIST 800-53 Control Mapping

Each receipt asserts compliance with the following NIST 800-53 controls. The mapping is recorded inside the receipts `nist_controls` field so it travels with the proof:

| Control | Title | How ProofLink supports |
|---|---|---|
| **AU-2** | Event Logging | Every autonomous action generates an event record |
| **AU-10** | Non-Repudiation | Hash chain + executor identity prevent denial |
| **SI-7** | Software, Firmware, and Information Integrity | Tamper-evident chain on the action trail |
| **SA-11** | Developer Testing and Evaluation | `test_result` field captured per receipt |

## Installation

```bash
npm install @itechsmart/prooflink-verifier
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
import { verifyReceipt } from '@itechsmart/prooflink-verifier'

const result = verifyReceipt(receipt, previousReceipt)

console.log(result.valid)           // true/false
console.log(result.tamper_detected) // true if hash or chain broken
console.log(result.checks)          // detailed check results
console.log(result.errors)          // list of failures
```


## How to Verify a Receipt (Step-by-Step)

The point of a public verifier is that anyone — auditor, journalist, competitor, customer — can independently confirm a ProofLink chain has not been edited. Here is the path from "I have a receipt ID" to "I trust this AI action happened exactly as claimed":

**1. Fetch the receipt**

```bash
curl https://verify.itechsmart.dev/api/verify/<receipt_id>
```

**2. Fetch the previous receipt** referenced by `previous_hash`:

```bash
curl https://verify.itechsmart.dev/api/receipts \
  | jq '.receipts[] | select(.sha256 == "<previous_hash>")'
```

**3. Re-compute the SHA-256** over the canonical JSON of every field except `sha256` itself, and check that it matches:

```typescript
import { verifyReceipt } from '@itechsmart/prooflink-verifier'
const result = verifyReceipt(receipt, previousReceipt)
console.log(result.valid)            // must be true
console.log(result.tamper_detected)  // must be false
```

**4. Walk the chain backward** to the genesis receipt with `verifyChain()`. A single broken link invalidates the chain from that point forward.

**5. Spot-check by random sampling.** Pick 5–10 random receipts; if every one verifies, the math says the entire chain is intact with overwhelming probability.

If you find a chain break, that is a real failure — please file a public issue on this repo.

### Verify an entire chain

```typescript
import { verifyChain } from '@itechsmart/prooflink-verifier'

const receipts = await fetchReceiptsFromLedger()
const result = verifyChain(receipts)

console.log(result.chain_valid)      // true if all receipts intact
console.log(result.tamper_detected)  // true if any tampering found
console.log(result.tamper_position)  // which position was altered
console.log(result.summary)          // human-readable summary
```

### Compute a hash yourself

```typescript
import { computeReceiptHash } from '@itechsmart/prooflink-verifier'

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

SDVOSB · CAGE: 172W2 · NVIDIA Inception
