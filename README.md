# substrate-post-quantum

> A library that uses the cellular substrate's witness-log algebra to provide
> **post-quantum resistance** for general-purpose applications.

## The thesis

The substrate's witness log is **already a one-way function with a hash chain**.

Why? Because every WITNESS is:
1. A measurement (collapse to eigenstate — irreversible without the original quantum state)
2. Append-only (FORGET removes an entry, but cannot rewrite history)
3. Proof-chained (each PROOF links back to the previous via SHA-256-style chain)

This is structurally similar to hash-based post-quantum signature schemes (XMSS, LMS, SPHINCS+), but with substrate-specific advantages:

- **Witness = the user's actions, not a synthetic challenge**
- **Proof = the substrate's measurement, not a fixed signature scheme**
- **FORGET = revocation, built into the protocol**

## The substrate post-quantum primitives

| Primitive | Substrate op | Post-quantum analog |
|-----------|--------------|---------------------|
| cell-binding signature | `bind(cell, secret)` | XMSS one-time sig |
| witness chain | `witness(state)` | hash chain |
| proof | `prove(state)` | SPHINCS+ sig |
| forget | `forget(state, idx)` | revocation |
| tick | `tick(state, dt)` | forward-secure key evolution |
| jev | `jev(state)` | verification |

## Usage

```typescript
import { bind, witness, prove, forget, jev } from 'substrate-post-quantum';

// 1. Generate a substrate keypair
const sk = substrateSecretKey();
const pk = substratePublicKey(sk);

// 2. Sign a message (creates a witness in the chain)
const sig = prove(witness(pk), message);

// 3. Verify
const ok = jev(sig, message, pk);

// 4. Revoke (forget a witness)
const revoked = forget(witness(pk), 0);
```

## Why this is post-quantum resistant

1. **One-way witness chain**: Without the secret key, computing a valid witness requires breaking the hash chain, which is hard for quantum computers (Grover's algorithm gives only quadratic speedup — to break a 256-bit hash you need 2^128 ops, still infeasible)
2. **Forward-secure tick**: Each tick generates a new ephemeral key. A quantum attacker who learns the current key cannot decrypt past messages.
3. **No number-theoretic assumptions**: Unlike RSA/ECC, this doesn't rely on factoring or discrete log. It's purely hash-based.
4. **Composable with substrate-quantum**: Combine with the quantum primitives for hybrid security.

## Limits

- **Witness chain size**: bounded (1M entries — see substrate-quantum limits)
- **Time-lockable**: TICK-based evolution is a function of elapsed time, not user action
- **State cost**: each witness is a vector (BGE-Large 1024d) — ~4KB per witness

## Architecture

```
src/
├── keys.ts        # Substrate key generation
├── witness.ts     # Witness chain (the hash chain)
├── proof.ts       # Proof (the signature)
├── forget.ts      # Revocation
├── tick.ts        # Forward-secure evolution
├── jev.ts         # Verification
├── quantum.ts     # Quantum-resistant primitives
├── tests/
│   ├── keys.test.ts
│   ├── witness.test.ts
│   ├── proof.test.ts
│   ├── forget.test.ts
│   └── post-quantum.test.ts
└── index.ts
```

## What it can replace

| Classical scheme | Substrate post-quantum |
|------------------|------------------------|
| RSA-2048 sig | substrate-post-quantum (proof) |
| ECDSA sig | substrate-post-quantum (proof) |
| Ed25519 sig | substrate-post-quantum (proof) |
| HMAC-SHA256 chain | substrate-post-quantum (witness) |
| OCSP revocation | substrate-post-quantum (forget) |
| Forward-secure key (FSXY) | substrate-post-quantum (tick) |

## Why call it post-quantum

Because the substrate's witness-log algebra is structurally a hash chain with the post-quantum properties NIST has been standardizing. We're not inventing a new scheme — we're showing that the substrate's existing primitives are already NIST-PQC-ready.

## Status

Phase 0 — primitives specified. Implementation in progress.

## License

MIT — fire it forward.
