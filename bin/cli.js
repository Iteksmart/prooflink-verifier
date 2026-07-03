#!/usr/bin/env node
/* ProofLink verifier CLI — verify receipts on the live public ledger.
 *
 *   npx @itechsmart/prooflink-verifier <receipt_id>   full crypto verify of one receipt
 *   npx @itechsmart/prooflink-verifier --chain [N]    pointer-linkage check on newest N (default 25)
 */
const { fetchAndVerifyReceipt, fetchAndVerifyChain } = require('../dist/index.js');

const GREEN = '\x1b[32m', RED = '\x1b[31m', DIM = '\x1b[2m', BOLD = '\x1b[1m', RESET = '\x1b[0m';

async function main() {
  const args = process.argv.slice(2);
  if (!args.length || args[0] === '--help' || args[0] === '-h') {
    console.log(`${BOLD}ProofLink Verifier${RESET} — don't trust the AI, trust the math.

Usage:
  prooflink-verify <receipt_id>     Fully verify one receipt (hash + payload + Ed25519)
  prooflink-verify --chain [N]      Verify pointer linkage of the newest N receipts (default 25)

Ledger: https://verify.itechsmart.dev  (no account required)`);
    process.exit(0);
  }

  if (args[0] === '--chain') {
    const n = parseInt(args[1], 10) || 25;
    const r = await fetchAndVerifyChain(n);
    console.log(`${BOLD}ProofLink public chain check${RESET} ${DIM}(newest ${r.receipts_verified} of ${r.ledger_total.toLocaleString()} receipts)${RESET}`);
    console.log(r.chain_valid
      ? `${GREEN}✓ ${r.summary}${RESET}`
      : `${RED}✗ ${r.summary}${RESET}`);
    if (r.errors.length) r.errors.slice(0, 5).forEach(e => console.log(`  ${RED}- ${e}${RESET}`));
    console.log(`${DIM}Ledger-reported chain_intact: ${r.ledger_chain_intact}${RESET}`);
    process.exit(r.chain_valid ? 0 : 1);
  }

  const id = args[0];
  const r = await fetchAndVerifyReceipt(id);
  if (!r.found) {
    console.log(`${RED}✗ Receipt ${id} not found on the public ledger${RESET}`);
    process.exit(2);
  }
  console.log(`${BOLD}ProofLink receipt ${id}${RESET}`);
  for (const c of r.checks) {
    console.log(`  ${c.passed ? GREEN + '✓' : RED + '✗'} ${c.name}${RESET} ${DIM}${c.detail}${RESET}`);
  }
  console.log(r.valid
    ? `${GREEN}${BOLD}VERIFIED${RESET} — hash intact, payload consistent, Ed25519 signature valid.`
    : r.tamper_detected
      ? `${RED}${BOLD}TAMPER DETECTED${RESET}`
      : `${RED}${BOLD}NOT FULLY VERIFIED${RESET} ${DIM}(see checks above)${RESET}`);
  process.exit(r.valid ? 0 : 1);
}

main().catch(e => { console.error(`${RED}Error: ${e.message}${RESET}`); process.exit(3); });
