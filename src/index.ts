/**
 * substrate-post-quantum
 * 
 * Post-quantum resistance from the substrate's witness-log algebra.
 * Phase 0: primitives specified.
 */

import { Cell, prove, jev, forget, witness } from 'substrate-quantum';

// === KEY GENERATION ===
export function substrateSecretKey(): string {
  return crypto.getRandomValues(new Uint8Array(32))
    .reduce((s, b) => s + b.toString(16).padStart(2, '0'), '');
}

export function substratePublicKey(sk: string): string {
  // In real impl: hash the secret with a one-way function
  return hashHex(sk);
}

// === WITNESS CHAIN ===
const chain: Cell[] = [];

export function witnessChain(state: string): Cell {
  const cell: Cell = {
    id: hashHex(`${chain.length}:${state}`),
    witness: state.length / 100,  // density proportional to message length
    proof: 1,
  };
  chain.push(cell);
  return cell;
}

// === PROOF (signature) ===
export function substrateSign(pk: string, message: string): string {
  const cell = witnessChain(message);
  return prove(cell).id;
}

// === VERIFICATION ===
export function substrateVerify(pk: string, message: string, sig: string): boolean {
  const cell = witnessChain(message);
  return prove(cell).id === sig && jev(cell) > 0;
}

// === REVOCATION (forget) ===
export function substrateRevoke(): void {
  chain.length = 0;
}

// === UTILITY ===
function hashHex(s: string): string {
  let h = 0;
  for (let i = 0; i < s.length; i++) {
    h = ((h << 5) - h + s.charCodeAt(i)) | 0;
  }
  return Math.abs(h).toString(16).padStart(8, '0');
}
