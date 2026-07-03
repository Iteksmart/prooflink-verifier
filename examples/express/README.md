# ProofLink Verifier × Express

```bash
npm i @itechsmart/prooflink-verifier express
node server.js
```

- `GET /verify/:id` — cryptographically verify a receipt (public ledger, no account)
- `GET /chain?limit=N` — verify pointer linkage of the newest N receipts
- `POST /protected` — gated by `requireValidReceipt()` middleware: the caller must send a header `x-prooflink-receipt: <id>` that passes verification, or the request is rejected 403

Pure verification — no tokens, no sealing. "Don't trust, verify."
