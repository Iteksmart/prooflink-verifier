/** 
 * ProofLink™ Verifier 
 * Open-source cryptographic verification logic for iTechSmart UAIO receipts 
 * 
 * Don't trust our AI. Trust the math. 
 * 
 * MIT License — https://github.com/Iteksmart/prooflink-verifier 
 */ 
import crypto from 'crypto' 

//──────────────────────────────────────────── 
// Types 
//──────────────────────────────────────────── 
export interface ProofLinkReceipt { 
  receipt_id: string 
  version: string 
  timestamp: string 
  container: string 
  executor: string 
  trigger: string 
  action: string 
  action_parameters: Record<string, unknown> 
  before_state: SystemState 
  after_state: SystemState 
  nist_controls: string[] 
  human_input: 'ZERO' | 'APPROVAL_REQUIRED' | 'MANUAL' 
  arbiter_policy: string 
  sha256: string 
  previous_hash: string | null 
  chain_position: number 
  opentimestamps_proof?: string 
} 

export interface SystemState { 
  snapshot_hash: string 
  healthy: boolean 
  metrics: Record<string, number | string> 
} 

export interface VerificationResult { 
  valid: boolean 
  receipt_id: string 
  checks: VerificationCheck[] 
  chain_position: number 
  tamper_detected: boolean 
  errors: string[] 
} 

export interface VerificationCheck { 
  name: string 
  passed: boolean 
  detail: string 
} 

//──────────────────────────────────────────── 
// Core Verification Logic 
//──────────────────────────────────────────── 
/** 
 * Compute the expected SHA-256 hash for a receipt. 
 * The hash covers all fields EXCEPT the sha256 field itself. 
 * This is the canonical hash function — open for inspection. 
 * 
 * @param receipt Receipt object without the sha256 field 
 * @returns Hexadecimal string of the computed SHA-256 hash 
 */ 
export function computeReceiptHash(receipt: Omit<ProofLinkReceipt, 'sha256'>): string { 
  const canonical = JSON.stringify({ 
    receipt_id: receipt.receipt_id, 
    version: receipt.version, 
    timestamp: receipt.timestamp, 
    container: receipt.container, 
    executor: receipt.executor, 
    trigger: receipt.trigger, 
    action: receipt.action, 
    action_parameters: receipt.action_parameters, 
    before_state: receipt.before_state, 
    after_state: receipt.after_state, 
    nist_controls: receipt.nist_controls, 
    human_input: receipt.human_input, 
    arbiter_policy: receipt.arbiter_policy, 
    previous_hash: receipt.previous_hash, 
    chain_position: receipt.chain_position, 
  }, null, 0) // deterministic — no pretty printing 
  return crypto.createHash('sha256').update(canonical, 'utf8').digest('hex') 
} 

/** 
 * Verify a single receipt's internal integrity. 
 * Returns true if the stored hash matches the recomputed hash. 
 */ 
export function verifyReceiptIntegrity(receipt: ProofLinkReceipt): VerificationCheck { 
  const { sha256, ...rest } = receipt 
  const computed = computeReceiptHash(rest) 
  const passed = computed === sha256 
  return { 
    name: 'receipt_integrity', 
    passed, 
    detail: passed ? `Hash matches: ${sha256.substring(0, 16)}...` : `Hash mismatch. Expected ${computed.substring(0, 16)}..., got ${sha256.substring(0, 16)}...`, 
  } 
} 

/** 
 * Verify that a receipt's previous_hash matches the prior receipt's sha256. 
 * This is what makes the chain tamper-evident — altering any receipt 
 * breaks every subsequent link. 
 */ 
export function verifyChainLink( 
  receipt: ProofLinkReceipt, 
  previousReceipt: ProofLinkReceipt | null 
): VerificationCheck { 
  if (receipt.chain_position === 0) { 
    const passed = receipt.previous_hash === null 
    return { 
      name: 'chain_link', 
      passed, 
      detail: passed ? 'Genesis receipt — no previous hash required' : `Genesis receipt should have null previous_hash, got: ${receipt.previous_hash}`, 
    } 
  } 
  if (!previousReceipt) { 
    return { 
      name: 'chain_link', 
      passed: false, 
      detail: `Cannot verify chain — previous receipt (position ${receipt.chain_position - 1}) not provided`, 
    } 
  } 
  const passed = receipt.previous_hash === previousReceipt.sha256 
  return { 
    name: 'chain_link', 
    passed, 
    detail: passed ? `Chain intact: links to receipt ${previousReceipt.receipt_id.substring(0, 8)}...` : `Chain BROKEN: expected ${previousReceipt.sha256.substring(0, 16)}..., got ${receipt.previous_hash?.substring(0, 16)}...`, 
  } 
} 

/** 
 * Verify that the chain_position is sequential. 
 */ 
export function verifyChainPosition( 
  receipt: ProofLinkReceipt, 
  previousReceipt: ProofLinkReceipt | null 
): VerificationCheck { 
  if (receipt.chain_position === 0) { 
    return { 
      name: 'chain_position', 
      passed: true, 
      detail: 'Genesis position: 0' 
    } 
  } 
  if (!previousReceipt) { 
    return { 
      name: 'chain_position', 
      passed: false, 
      detail: 'Cannot verify position without previous receipt', 
    } 
  } 
  const passed = receipt.chain_position === previousReceipt.chain_position + 1 
  return { 
    name: 'chain_position', 
    passed, 
    detail: passed ? `Position ${receipt.chain_position} follows ${previousReceipt.chain_position}` : `Position gap detected: ${previousReceipt.chain_position} → ${receipt.chain_position}`, 
  } 
} 

/** 
 * Verify timestamp ordering — receipts must be chronologically ordered. 
 */ 
export function verifyTimestampOrder( 
  receipt: ProofLinkReceipt, 
  previousReceipt: ProofLinkReceipt | null 
): VerificationCheck { 
  if (!previousReceipt) { 
    return { 
      name: 'timestamp_order', 
      passed: true, 
      detail: 'No previous receipt to compare' 
    } 
  } 
  const current = new Date(receipt.timestamp).getTime() 
  const previous = new Date(previousReceipt.timestamp).getTime() 
  const passed = current >= previous 
  return { 
    name: 'timestamp_order', 
    passed, 
    detail: passed ? `Timestamp order valid: ${receipt.timestamp} >= ${previousReceipt.timestamp}` : `Timestamp order INVALID: ${receipt.timestamp} precedes ${previousReceipt.timestamp}`, 
  } 
} 

/** 
 * Verify the receipt schema has all required fields. 
 */ 
export function verifyReceiptSchema(receipt: unknown): VerificationCheck { 
  const required = [ 
    'receipt_id', 
    'version', 
    'timestamp', 
    'container', 
    'executor', 
    'trigger', 
    'action', 
    'before_state', 
    'after_state', 
    'sha256', 
    'chain_position', 
    'human_input', 
  ] 
  const r = receipt as Record<string, unknown> 
  const missing = required.filter(field => !(field in r) || r[field] === undefined) 
  const passed = missing.length === 0 
  return { 
    name: 'schema_valid', 
    passed, 
    detail: passed ? 'All required fields present' : `Missing required fields: ${missing.join(', ')}`, 
  } 
} 

/** 
 * Full verification of a single receipt. 
 * Pass previousReceipt=null for genesis (first) receipt. 
 */ 
export function verifyReceipt( 
  receipt: ProofLinkReceipt, 
  previousReceipt: ProofLinkReceipt | null = null 
): VerificationResult { 
  const checks: VerificationCheck[] = [ 
    verifyReceiptSchema(receipt), 
    verifyReceiptIntegrity(receipt), 
    verifyChainLink(receipt, previousReceipt), 
    verifyChainPosition(receipt, previousReceipt), 
    verifyTimestampOrder(receipt, previousReceipt), 
  ] 
  const errors = checks 
    .filter(c => !c.passed) 
    .map(c => `[${c.name}] ${c.detail}`) 
  const tamperDetected = !checks.find(c => c.name === 'receipt_integrity')?.passed || !checks.find(c => c.name === 'chain_link')?.passed 
  return { 
    valid: errors.length === 0, 
    receipt_id: receipt.receipt_id, 
    checks, 
    chain_position: receipt.chain_position, 
    tamper_detected: tamperDetected, 
    errors, 
  } 
} 

/** 
 * Verify an entire chain of receipts. 
 * Returns a result for each receipt plus an overall chain validity boolean. 
 */ 
export function verifyChain(receipts: ProofLinkReceipt[]): { 
  chain_valid: boolean 
  tamper_detected: boolean 
  tamper_position: number | null 
  results: VerificationResult[] 
  summary: string 
} { 
  if (receipts.length === 0) { 
    return { 
      chain_valid: false, 
      tamper_detected: false, 
      tamper_position: null, 
      results: [], 
      summary: 'Empty chain — nothing to verify', 
    } 
  } 
  // Sort by chain_position 
  const sorted = [...receipts].sort((a, b) => a.chain_position - b.chain_position) 
  const results: VerificationResult[] = [] 
  let tamperPosition: number | null = null 
  for (let i = 0; i < sorted.length; i++) { 
    const result = verifyReceipt(sorted[i], i > 0 ? sorted[i - 1] : null) 
    results.push(result) 
    if (result.tamper_detected && tamperPosition === null) { 
      tamperPosition = sorted[i].chain_position 
    } 
  } 
  const chainValid = results.every(r => r.valid) 
  const tamperDetected = tamperPosition !== null 
  return { 
    chain_valid: chainValid, 
    tamper_detected: tamperDetected, 
    tamper_position: tamperPosition, 
    results, 
    summary: chainValid ? `Chain valid — ${receipts.length} receipts verified, no tampering detected` : `Chain INVALID — tampering detected at position ${tamperPosition}`, 
  } 
} 

//──────────────────────────────────────────── 
// Public API 
//──────────────────────────────────────────── 
export const ProofLinkVerifier = { 
  computeHash: computeReceiptHash, 
  verifyReceipt, 
  verifyChain, 
  verifyIntegrity: verifyReceiptIntegrity, 
  verifyChainLink, 
} 
export default ProofLinkVerifier