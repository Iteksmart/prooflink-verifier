// ProofLink Verifier × Next.js — public receipt-verification route.
//
//   npm i @itechsmart/prooflink-verifier
//   // GET /api/verify/c58347c60394a21f  ->  { valid, checks }
//
// Node runtime (node:crypto for Ed25519). Verifies against the public ledger;
// no account, no secrets. The leaner verify-only sibling of @itechsmart/prooflink.

import { fetchAndVerifyReceipt } from "@itechsmart/prooflink-verifier";
import { NextResponse } from "next/server";

export const runtime = "nodejs";

export async function GET(_req: Request, { params }: { params: { id: string } }) {
  try {
    const r = await fetchAndVerifyReceipt(params.id);
    return NextResponse.json({
      receipt_id: params.id,
      valid: r.valid,
      checks: r.checks,
      verify_url: `https://verify.itechsmart.dev/${params.id}`,
    }, { status: r.valid ? 200 : 422 });
  } catch (e) {
    return NextResponse.json({ error: (e as Error).message }, { status: 404 });
  }
}
