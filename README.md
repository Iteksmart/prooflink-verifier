# ProofLink™ Verifier

[![CI](https://github.com/Iteksmart/prooflink-verifier/actions/workflows/ci.yml/badge.svg)](https://github.com/Iteksmart/prooflink-verifier/actions/workflows/ci.yml) [![npm](https://img.shields.io/npm/v/%40itechsmart%2Fprooflink-verifier)](https://www.npmjs.com/package/@itechsmart/prooflink-verifier) [![license](https://img.shields.io/badge/license-MIT-blue)](./LICENSE) [![Verify Live](https://img.shields.io/badge/verify-live-00A870)](https://verify.itechsmart.dev) [![ledger](https://img.shields.io/badge/live_ledger-80%2C000%2B_receipts-22d3ee)](https://verify.itechsmart.dev)

> **Every other AI-accountability standard is a PDF. ProofLink is a running ledger of
> 80,000+ cryptographically-sealed AI actions you can verify right now — not a spec, a
> live chain.** → **[verify.itechsmart.dev](https://verify.itechsmart.dev)**

**Open-source, zero-dependency cryptographic verification logic for iTechSmart UAIO
receipts** — the reference implementation of the
[ProofLink Receipt Standard **v3.0**](https://github.com/Iteksmart/prooflink-standard/blob/main/ProofLink-Receipt-Standard-v3.md).

**Independently verify what an autonomous AI actually did.**

ProofLink is the **Trust & Accountability Layer for Autonomous AI** by [iTechSmart Inc.](https://itechsmart.dev) Every autonomous action seals a cryptographic receipt — SHA-256 hash-chained, **Ed25519-signed**, Bitcoin-anchored via OpenTimestamps — into a public ledger.

This package is the open-source verifier. You don't need an account. You don't need a demo. You don't need to trust iTechSmart.

> **Don't trust the AI. Trust the math.**


## Framework examples

Credential-free verification wired into common stacks — see [`examples/`](./examples):

| Example | Stack |
|---|---|
| [Express](./examples/express) | `/verify/:id` + `/chain` + `requireValidReceipt` middleware gate |
| [Next.js](./examples/nextjs) | `/api/verify/[id]` server-side verification route |
| [GitHub Actions](./examples/github-action) | CI gate — fail the build unless referenced receipts verify |
| [Node audit](./examples/node-audit) | cron/monitoring; non-zero exit on any tamper |


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

## Verify a real receipt in 30 seconds

```bash
# Full cryptographic verification of one receipt from the live public ledger:
npx @itechsmart/prooflink-verifier 450ebfeb2a1cb00d

#   ✓ hash_integrity            SHA256(canonical_bytes) == hash_sha256
#   ✓ canonical_rederivation    re-derived canonical bytes match
#   ✓ ed25519_signature         Ed25519 OK
#   VERIFIED

# Pointer-linkage check on the newest 25 receipts in the chain:
npx @itechsmart/prooflink-verifier --chain 25
```

Grab any receipt ID from the live ledger at **[verify.itechsmart.dev](https://verify.itechsmart.dev)** — no account, no demo, no trust required.

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

## What gets verified (schema v3 — the live ledger format)

Every v3 receipt is sealed like this on the platform side:

```
payload          = all receipt fields EXCEPT (canonical_bytes, signature, hash_sha256)
                   — including prev_hash and chain_position, so the chain link
                   itself is covered by the hash AND the signature
canonical_bytes  = canonical JSON of payload (sorted keys, compact, UTF-8), hex-encoded
hash_sha256      = SHA-256(canonical_bytes)
signature        = Ed25519 over the raw canonical bytes (32-byte public key, hex)
```

The verifier independently re-checks all three:

| Check | What it proves |
|---|---|
| `hash_integrity` | The recorded hash really is the SHA-256 of the signed bytes |
| `payload_consistency` | The fields you're reading are exactly what was hashed and signed — nothing displayed differs from the sealed record |
| `signature_valid` | The Ed25519 signature verifies against the canonical bytes |

Chain-level checks (`--chain`, `verifyPublicChain`): every receipt's `previous_hash` must equal the prior receipt's `sha256`, positions must be sequential, timestamps ordered. Altering any historic receipt breaks every receipt after it — the same principle as Bitcoin's blockchain, applied to AI accountability.

Beyond this library: receipts are also anchored to the **Bitcoin blockchain via OpenTimestamps**, are **SCITT-compatible** (IETF architecture), and carry **W3C Verifiable Credential** envelopes plus clause-level **EU AI Act Article 12(1)/(2)/(4)** and NIST AI RMF mappings. See the [public verification spec](https://verify.itechsmart.dev/api/how-to-verify).

---

## Installation & library usage

```bash
npm install @itechsmart/prooflink-verifier
```

```typescript
import {
  fetchAndVerifyReceipt,   // full crypto against the live ledger
  fetchAndVerifyChain,     // pointer-linkage check on the newest N receipts
  verifyReceiptV3,         // verify a v3 receipt object you already have
  verifyPublicChain,       // verify a list from /api/receipts
  verify, verifyAnyChain,  // schema-aware: auto-detects v3 vs legacy receipts
} from '@itechsmart/prooflink-verifier'

const result = await fetchAndVerifyReceipt('450ebfeb2a1cb00d')
console.log(result.valid)            // true
console.log(result.checks)           // hash_integrity, payload_consistency, signature_valid

const chain = await fetchAndVerifyChain(50)
console.log(chain.chain_valid)       // true
console.log(chain.ledger_total)      // 80,000+ and counting
```

Public API endpoints (no auth):

- `GET https://verify.itechsmart.dev/api/receipt/<id>` — full receipt incl. `canonical_bytes` + `signature`
- `GET https://verify.itechsmart.dev/api/receipts?limit=N` — newest receipts (summary)
- `GET https://verify.itechsmart.dev/api/stats` — live totals + chain integrity
- `GET https://verify.itechsmart.dev/api/how-to-verify` — the full verification spec

**For AI agents:** the same verification is exposed over MCP at [mcp.itechsmart.dev](https://mcp.itechsmart.dev) — Claude, GPT, Copilot and Cursor can verify receipts directly (17 tools).

---

## Legacy schema (v1)

Earlier receipts used a fixed-field schema (`container`, `executor`, `trigger`, …). The original verification functions (`verifyReceipt`, `verifyChain`, `computeReceiptHash`) still support it, and `verify()` / `verifyAnyChain()` auto-detect which schema you're holding.

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
- Test vectors

---

## Why this exists

Regulators (EU AI Act Article 12, enforcement August 2, 2026), auditors, and customers increasingly ask one question about autonomous AI: **"Prove it."**

Audit logs can be edited. Dashboards can be wrong. Vendor attestations require trust. A hash-chained, signed, Bitcoin-anchored receipt that *anyone* can verify with open-source code requires none of those things.

---

## About iTechSmart

iTechSmart Inc. builds UAIO (Unified Autonomous IT Operations) — the first enterprise platform that autonomously detects, remediates, and cryptographically proves every infrastructure action — and operates ProofLink, the Trust & Accountability Layer for Autonomous AI.

- Product: [prooflink.itechsmart.dev](https://prooflink.itechsmart.dev)
- Verify receipts: [verify.itechsmart.dev](https://verify.itechsmart.dev)
- Website: [itechsmart.dev](https://itechsmart.dev)
- Whitepaper: [whitepaper.itechsmart.dev](https://whitepaper.itechsmart.dev)

SDVOSB · CAGE: 172W2 · UEI: ZCPFX4N86G36 · NVIDIA Inception

## License

MIT © iTechSmart Inc. — use freely, audit openly, verify everything. ProofLink™ is a registered federal trademark of iTechSmart Inc.
