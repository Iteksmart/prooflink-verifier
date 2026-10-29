import { describe, it, expect } from 'vitest';
import { generateKeyPairSync, sign, createHash } from 'node:crypto';
import { canonicalize, verifyReceiptV3, verifyV3, verifyChainV3, PUBLISHED_PUBLIC_KEY, type V3Receipt } from './standard-v3';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

const original: V3Receipt = JSON.parse(readFileSync(join(process.cwd(),'test/fixtures/v3_receipt.json'),'utf8'));
function forged() {
  const receipt=structuredClone(original);receipt.outcome='FORGED TEST OUTCOME';
  const {privateKey,publicKey}=generateKeyPairSync('ed25519');
  const key=publicKey.export({format:'der',type:'spki'}).subarray(-32).toString('hex');
  const payload=Object.fromEntries(Object.entries(receipt).filter(([k])=>!['canonical_bytes','signature','hash_sha256'].includes(k)));
  const bytes=canonicalize(payload);
  receipt.canonical_bytes=bytes.toString('hex');receipt.hash_sha256=createHash('sha256').update(bytes).digest('hex');
  receipt.signature={algorithm:'Ed25519',public_key:key,value:sign(null,bytes,privateKey).toString('hex'),signs:'canonical_bytes'};
  return {receipt,key};
}
describe('issuer trust boundary',()=>{
  it('does not call an empty chain verified',()=>{expect(verifyChainV3([]).chain_valid).toBe(false);});
  it('accepts the pinned issuer and does not claim Bitcoin verification',()=>{
    const result=verifyReceiptV3(original);expect(result.valid).toBe(true);expect(result.signer_trusted).toBe(true);expect(result.bitcoin_verified).toBe(false);
  });
  it('rejects a valid signature from an untrusted issuer',()=>{
    const {receipt}=forged();const result=verifyReceiptV3(receipt);
    expect(result.signature_valid).toBe(true);expect(result.signer_trusted).toBe(false);expect(result.valid).toBe(false);
    expect(verifyChainV3([receipt]).chain_valid).toBe(false);
  });
  it('allows explicit custom issuers and rejects revoked/empty trust sets',()=>{
    const {receipt,key}=forged();expect(verifyV3(receipt,undefined,{trustedPublicKeys:[key]})).toBe(true);
    expect(verifyV3(receipt,undefined,{trustedPublicKeys:[key],revokedPublicKeys:[key]})).toBe(false);
    expect(verifyV3(original,undefined,{revokedPublicKeys:[PUBLISHED_PUBLIC_KEY]})).toBe(false);
    expect(verifyV3(original,undefined,{trustedPublicKeys:[]})).toBe(false);
  });
  it.each([['algorithm','RSA'],['signs','hash_sha256'],['signed_payload','other'],['value',original.signature.value+'zz'],['public_key',PUBLISHED_PUBLIC_KEY+'zz']])('rejects invalid signature metadata: %s',(field,value)=>{
    const data=structuredClone(original);(data.signature as unknown as Record<string,unknown>)[field]=value;expect(verifyV3(data)).toBe(false);
  });
  it.each([null,undefined,[], 'receipt', {schema_version:'99.0'}])('fails closed on malformed input %j',value=>{
    expect(verifyReceiptV3(value as V3Receipt).valid).toBe(false);
  });
});
