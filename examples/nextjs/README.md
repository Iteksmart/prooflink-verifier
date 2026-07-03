# ProofLink Verifier × Next.js (App Router)

```bash
npm i @itechsmart/prooflink-verifier
```

Copy `app/api/verify/[id]/route.ts` into your app — `GET /api/verify/<receipt_id>`
returns `{ valid, checks }`, verified server-side against the public ledger.
Node runtime (uses `node:crypto`). This is the leaner, verify-only sibling of the
full `@itechsmart/prooflink` SDK.
