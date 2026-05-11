/**
 * ProofLink Verifier — Test Suite
 * These tests are the canonical examples of valid and tampered receipts.
 * Run: npm test
 */

import {
  computeReceiptHash,
  verifyReceipt,
  verifyChain,
  ProofLinkReceipt,
} from './prooflink-verifier'

// ─────────────────────────────────────────────
// Fixtures
// ─────────────────────────────────────────────

function makeReceipt(overrides: Partial<ProofLinkReceipt> = {}): ProofLinkReceipt {
  const base: Omit<ProofLinkReceipt, 'sha256'> = {
    receipt_id: 'a1b2c3d4e5f6a7b8',
    version: '1.0',
    timestamp: '2026-05-08T09:00:00.000Z',
    container: 'suite-api-7d9f8b-xk2p9',
    executor: 'OctoAI/Nemotron-Ultra-253B',
    trigger: 'OOMKilled — CrashLoopBackOff',
    action: 'kubectl patch memory 512Mi→1024Mi + rollout restart',
    action_parameters: { memory_limit: '1024Mi', restart_policy: 'rollout' },
    before_state: { snapshot_hash: 'dead0000', healthy: false, metrics: { restarts: 3 } },
    after_state: { snapshot_hash: 'cafe1234', healthy: true, metrics: { restarts: 0 } },
    nist_controls: ['SI-2', 'SI-7', 'AU-2'],
    human_input: 'ZERO',
    arbiter_policy: 'auto-remediation-v2',
    previous_hash: null,
    chain_position: 0,
    ...overrides,
  }
  const sha256 = computeReceiptHash(base)
  return { ...base, sha256, ...overrides }
}

// ─────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────

describe('computeReceiptHash', () => {
  it('produces a 64-character hex string', () => {
    const receipt = makeReceipt()
    const { sha256, ...rest } = receipt
    const hash = computeReceiptHash(rest)
    expect(hash).toHaveLength(64)
    expect(hash).toMatch(/^[0-9a-f]{64}$/)
  })

  it('is deterministic — same input always produces same hash', () => {
    const receipt = makeReceipt()
    const { sha256, ...rest } = receipt
    const h1 = computeReceiptHash(rest)
    const h2 = computeReceiptHash(rest)
    expect(h1).toBe(h2)
  })

  it('changes when any field changes', () => {
    const receipt = makeReceipt()
    const { sha256, ...rest } = receipt
    const original = computeReceiptHash(rest)
    const tampered = computeReceiptHash({ ...rest, action: 'TAMPERED ACTION' })
    expect(original).not.toBe(tampered)
  })
})

describe('verifyReceipt — valid receipt', () => {
  it('passes all checks for a valid genesis receipt', () => {
    const receipt = makeReceipt()
    const result = verifyReceipt(receipt, null)
    expect(result.valid).toBe(true)
    expect(result.tamper_detected).toBe(false)
    expect(result.errors).toHaveLength(0)
    expect(result.checks.every(c => c.passed)).toBe(true)
  })

  it('passes all checks for a valid chained receipt', () => {
    const r0 = makeReceipt()
    const r1 = makeReceipt({
      receipt_id: 'b2c3d4e5f6a7b8c9',
      timestamp: '2026-05-08T09:01:00.000Z',
      previous_hash: r0.sha256,
      chain_position: 1,
    })
    // Fix sha256 for r1
    const { sha256, ...r1rest } = r1
    const r1fixed: ProofLinkReceipt = { ...r1rest, sha256: computeReceiptHash(r1rest) }

    const result = verifyReceipt(r1fixed, r0)
    expect(result.valid).toBe(true)
    expect(result.tamper_detected).toBe(false)
  })
})

describe('verifyReceipt — tampered receipt', () => {
  it('detects hash tampering when action is changed', () => {
    const receipt = makeReceipt()
    const tampered = { ...receipt, action: 'DROP TABLE production' }
    // sha256 still points to original action
    const result = verifyReceipt(tampered, null)
    expect(result.valid).toBe(false)
    expect(result.tamper_detected).toBe(true)
    expect(result.errors.some(e => e.includes('receipt_integrity'))).toBe(true)
  })

  it('detects chain break when previous_hash is wrong', () => {
    const r0 = makeReceipt()
    const r1 = makeReceipt({
      receipt_id: 'b2c3d4e5f6a7b8c9',
      timestamp: '2026-05-08T09:01:00.000Z',
      previous_hash: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      chain_position: 1,
    })
    const { sha256, ...r1rest } = r1
    const r1fixed: ProofLinkReceipt = { ...r1rest, sha256: computeReceiptHash(r1rest) }

    const result = verifyReceipt(r1fixed, r0)
    expect(result.valid).toBe(false)
    expect(result.errors.some(e => e.includes('chain_link'))).toBe(true)
  })

  it('detects timestamp ordering violation', () => {
    const r0 = makeReceipt({ timestamp: '2026-05-08T09:01:00.000Z' })
    const r1base: Omit<ProofLinkReceipt, 'sha256'> = {
      receipt_id: 'b2c3d4e5',
      version: '1.0',
      timestamp: '2026-05-08T09:00:00.000Z', // BEFORE r0
      container: 'suite-api',
      executor: 'OctoAI',
      trigger: 'test',
      action: 'restart',
      action_parameters: {},
      before_state: { snapshot_hash: 'a', healthy: false, metrics: {} },
      after_state: { snapshot_hash: 'b', healthy: true, metrics: {} },
      nist_controls: ['AU-2'],
      human_input: 'ZERO',
      arbiter_policy: 'auto',
      previous_hash: r0.sha256,
      chain_position: 1,
    }
    const r1: ProofLinkReceipt = { ...r1base, sha256: computeReceiptHash(r1base) }

    const result = verifyReceipt(r1, r0)
    expect(result.valid).toBe(false)
    expect(result.errors.some(e => e.includes('timestamp_order'))).toBe(true)
  })
})

describe('verifyChain', () => {
  it('validates a clean chain of 5 receipts', () => {
    const receipts: ProofLinkReceipt[] = []
    let prevHash: string | null = null

    for (let i = 0; i < 5; i++) {
      const base: Omit<ProofLinkReceipt, 'sha256'> = {
        receipt_id: `receipt-${i}`,
        version: '1.0',
        timestamp: `2026-05-08T09:0${i}:00.000Z`,
        container: 'suite-api',
        executor: 'OctoAI',
        trigger: `trigger-${i}`,
        action: `action-${i}`,
        action_parameters: {},
        before_state: { snapshot_hash: `before-${i}`, healthy: false, metrics: {} },
        after_state: { snapshot_hash: `after-${i}`, healthy: true, metrics: {} },
        nist_controls: ['AU-2'],
        human_input: 'ZERO',
        arbiter_policy: 'auto',
        previous_hash: prevHash,
        chain_position: i,
      }
      const sha256 = computeReceiptHash(base)
      receipts.push({ ...base, sha256 })
      prevHash = sha256
    }

    const result = verifyChain(receipts)
    expect(result.chain_valid).toBe(true)
    expect(result.tamper_detected).toBe(false)
    expect(result.tamper_position).toBeNull()
    expect(result.results).toHaveLength(5)
  })

  it('detects tampering at position 2 in a 5-receipt chain', () => {
    const receipts: ProofLinkReceipt[] = []
    let prevHash: string | null = null

    for (let i = 0; i < 5; i++) {
      const base: Omit<ProofLinkReceipt, 'sha256'> = {
        receipt_id: `receipt-${i}`,
        version: '1.0',
        timestamp: `2026-05-08T09:0${i}:00.000Z`,
        container: 'suite-api',
        executor: 'OctoAI',
        trigger: `trigger-${i}`,
        action: `action-${i}`,
        action_parameters: {},
        before_state: { snapshot_hash: `before-${i}`, healthy: false, metrics: {} },
        after_state: { snapshot_hash: `after-${i}`, healthy: true, metrics: {} },
        nist_controls: ['AU-2'],
        human_input: 'ZERO',
        arbiter_policy: 'auto',
        previous_hash: prevHash,
        chain_position: i,
      }
      const sha256 = computeReceiptHash(base)
      receipts.push({ ...base, sha256 })
      prevHash = sha256
    }

    // Tamper with receipt at position 2
    receipts[2] = { ...receipts[2], action: 'DROP TABLE receipts' }

    const result = verifyChain(receipts)
    expect(result.chain_valid).toBe(false)
    expect(result.tamper_detected).toBe(true)
    expect(result.tamper_position).toBe(2)
  })
})
