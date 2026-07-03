# @itechsmart/prooflink-verifier — Framework Examples

Independent, credential-free verification of ProofLink receipts, wired into common stacks.
Every example uses the published [`@itechsmart/prooflink-verifier`](https://www.npmjs.com/package/@itechsmart/prooflink-verifier)
and the live public ledger — no account, no tokens. **Don't trust — verify.**

| Example | Stack | Shows |
|---|---|---|
| [express](./express) | Express (Node) | `/verify/:id` + `/chain` endpoints + a `requireValidReceipt` middleware gate |
| [nextjs](./nextjs) | Next.js App Router | `/api/verify/[id]` verification route (server-side) |
| [github-action](./github-action) | GitHub Actions | CI gate — fail the build unless referenced receipts verify |
| [node-audit](./node-audit) | Node script | cron/monitoring audit; non-zero exit on any tamper |

Verify-only. To also **seal** receipts (agent/API frameworks), see the full SDK
[`@itechsmart/prooflink`](https://www.npmjs.com/package/@itechsmart/prooflink) and its examples.
