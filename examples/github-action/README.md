# ProofLink Verifier × GitHub Actions (CI verification gate)

Copy `verify-receipts.yml` into `.github/workflows/`. It fails the build if any
ProofLink receipt id listed in a repo `RECEIPTS` file (one per line) does not
cryptographically verify against the public ledger, and also confirms the public
chain's newest entries link cleanly.

Use it to **prove in CI** that the autonomous actions behind a change actually
happened and weren't tampered with — turning ProofLink receipts into a merge/deploy gate.
No secrets required; verification is public.
