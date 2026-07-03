# ProofLink Verifier × Node audit (cron / monitoring)

```bash
npm i @itechsmart/prooflink-verifier
node audit.mjs          # verify newest 50 + chain linkage; exit non-zero on any failure
node audit.mjs <id>     # deep-verify one receipt
```

Designed for a cron job or healthcheck: it exits non-zero the moment a receipt
fails verification or the chain linkage breaks, so it wires straight into
alerting. Verifies against the public ledger — no account, no secrets.
