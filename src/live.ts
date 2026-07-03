/**
 * Live-ledger helpers: fetch receipts from verify.itechsmart.dev and verify
 * them with the Standard v3.0 verifier (see ./standard-v3), plus a
 * pointer-linkage check for the public summary list (/api/receipts).
 */
import { verifyReceiptV3, type V3Receipt, type V3Result } from './standard-v3';

export const DEFAULT_LEDGER = 'https://verify.itechsmart.dev';

export interface PublicChainReceipt {
  receipt_id: string;
  chain_position: number;
  previous_hash: string;
  sha256: string;
  timestamp: string;
  [key: string]: unknown;
}

export interface PublicChainResult {
  chain_valid: boolean;
  tamper_detected: boolean;
  receipts_verified: number;
  tamper_position: number | null;
  summary: string;
  errors: string[];
}

/**
 * Pointer-linkage verification for the public summary list (/api/receipts):
 * previous_hash links, monotonic chain positions, timestamp order.
 * Full crypto per receipt requires the detail endpoint (see fetchAndVerifyReceipt).
 */
export function verifyPublicChain(receipts: PublicChainReceipt[]): PublicChainResult {
  const errors: string[] = [];
  let tamperPosition: number | null = null;
  const sorted = [...receipts].sort((a, b) => a.chain_position - b.chain_position);
  for (let i = 1; i < sorted.length; i++) {
    const prev = sorted[i - 1];
    const cur = sorted[i];
    if (cur.chain_position !== prev.chain_position + 1) {
      errors.push(`Gap between positions ${prev.chain_position} and ${cur.chain_position}`);
      tamperPosition = tamperPosition ?? cur.chain_position;
      continue;
    }
    if (cur.previous_hash !== prev.sha256) {
      errors.push(`Broken link at position ${cur.chain_position}: previous_hash does not match prior sha256`);
      tamperPosition = tamperPosition ?? cur.chain_position;
    }
    if (new Date(cur.timestamp).getTime() < new Date(prev.timestamp).getTime()) {
      errors.push(`Timestamp regression at position ${cur.chain_position}`);
    }
  }
  const ok = errors.length === 0;
  return {
    chain_valid: ok,
    tamper_detected: !ok,
    receipts_verified: sorted.length,
    tamper_position: tamperPosition,
    summary: ok
      ? `Chain VALID — ${sorted.length} receipts, pointer linkage intact`
      : `Chain INVALID — ${errors.length} problem(s), first at position ${tamperPosition}`,
    errors,
  };
}

/** Fetch a receipt by id from the public ledger and fully verify it (Standard v3.0). */
export async function fetchAndVerifyReceipt(
  receiptId: string,
  base: string = DEFAULT_LEDGER,
): Promise<V3Result & { receipt_id: string; found: boolean }> {
  const res = await fetch(`${base}/api/receipt/${encodeURIComponent(receiptId)}`);
  if (!res.ok) {
    return { receipt_id: receiptId, found: false, valid: false, id: receiptId, checks: [], errors: [`HTTP ${res.status} from ledger`] };
  }
  const body = (await res.json()) as { found?: boolean; receipt?: V3Receipt };
  if (!body.found || !body.receipt) {
    return { receipt_id: receiptId, found: false, valid: false, id: receiptId, checks: [], errors: ['Receipt not found'] };
  }
  return { receipt_id: receiptId, found: true, ...verifyReceiptV3(body.receipt) };
}

/** Fetch the newest N receipts from the public ledger and verify pointer linkage. */
export async function fetchAndVerifyChain(
  limit = 25,
  base: string = DEFAULT_LEDGER,
): Promise<PublicChainResult & { ledger_total: number; ledger_chain_intact: boolean }> {
  const res = await fetch(`${base}/api/receipts?limit=${limit}`);
  const body = (await res.json()) as { total: number; chain_intact: boolean; receipts: PublicChainReceipt[] };
  return { ...verifyPublicChain(body.receipts || []), ledger_total: body.total, ledger_chain_intact: body.chain_intact };
}
