// ProofLink Verifier × Node audit script — for cron / monitoring.
//
//   npm i @itechsmart/prooflink-verifier
//   node audit.mjs           # verify newest 50 receipts + chain linkage
//   node audit.mjs <id>      # deep-verify one receipt
//
// Exits non-zero if any receipt fails verification or the chain is broken —
// so it drops straight into a cron job, healthcheck, or alerting pipeline.

import { fetchAndVerifyReceipt, fetchAndVerifyChain } from "@itechsmart/prooflink-verifier";

const arg = process.argv[2];

if (arg) {
  const r = await fetchAndVerifyReceipt(arg);
  for (const c of r.checks) console.log(`  ${c.passed ? "✓" : "✗"} ${c.name}`);
  console.log(r.valid ? `VERIFIED ${arg}` : `NOT VERIFIED ${arg}`);
  process.exit(r.valid ? 0 : 1);
}

const limit = 50;
const r = await fetchAndVerifyChain(limit);
console.log(`Ledger: ${r.ledger_total?.toLocaleString?.() ?? "?"} receipts · reported chain_intact=${r.ledger_chain_intact}`);
console.log(r.chain_valid
  ? `✓ pointer linkage intact across newest ${r.receipts_verified}`
  : `✗ CHAIN PROBLEM: ${r.summary}`);
if (!r.chain_valid) {
  r.errors.slice(0, 10).forEach((e) => console.error(`  - ${e}`));
  process.exit(1);
}
process.exit(0);
