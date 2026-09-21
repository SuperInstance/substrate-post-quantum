# substrate-post-quantum

Post-quantum cryptographic primitives. Quantum-safe alternatives to RSA/ECC.

```typescript
import { buildMerkleTree, merkleProof, verifyMerkleProof,
  otsGenerate, otsSign, otsVerify,
  Poly, lweGenerate, lweEncrypt, lweDecrypt,
  commit, verifyCommitment,
  HashChainPRNG,
  pqGenerate, pqSign, pqVerify } from 'substrate-post-quantum';

// === HASH-BASED SIGNATURE (XMSS-style) ===
const kp = pqGenerate(4);   // 4 one-time signatures in a Merkle tree
const message = new TextEncoder().encode('hello world');
const sig = pqSign(kp.privateKey, message, 1);
pqVerify(kp.publicKey, message, sig);   // true

// === LATTICE-BASED KEM (toy Ring-LWE) ===
const lwe = lweGenerate(8, 101);
const message = Poly.zero(8, 101);
const ct = lweEncrypt(lwe.pk, message);
const decrypted = lweDecrypt(lwe.sk, ct);

// === HASH COMMITMENTS ===
const c = commit('secret value');
verifyCommitment(c.commitment, 'secret value');  // true

// === MERKLE TREES ===
const tree = buildMerkleTree([sha256('a'), sha256('b'), sha256('c')]);
const path = merkleProof(tree, 1);
verifyMerkleProof(tree.hash, sha256('b'), 1, path);  // true
```

## The math

### Why post-quantum?

RSA, ECDSA, DH all break under Shor's algorithm (1994). Once a sufficiently large quantum computer exists (~4000 logical qubits with error correction), all classical public-key crypto is broken.

Grover's algorithm halves the security of symmetric crypto (search in 2^n becomes √2^n). Doubling key sizes compensates.

**Post-quantum primitives survive because they're based on different hard problems.**

### Hash-based signatures (XMSS, SPHINCS+)

Security: only requires hash function (SHA-256 here) being collision-resistant and preimage-resistant.

```
sk = random 32 bytes
pk[i] = SHA-256^(MAX + i) (sk)   for i in [0, n)
sig[i] = SHA-256^(MAX + i - count_i) (sk)
```

Each signature reveals some of the hash chain, so each OTS key can only sign ONE message safely. Multiple OTS keys are arranged in a Merkle tree, signing an OTS index + message.

**Security under Grover**: SHA-256 has ~128-bit post-quantum security (Grover halves 256-bit preimage resistance to 128). NIST-approved: SPHINCS+, XMSS.

### Lattice-based KEM (Kyber, ML-KEM)

Security: Learning With Errors (LWE) over polynomial rings. The "hard problem" is: given `b = a·s + e` (where s, e are small), recover s.

Best known quantum attack is exponential in n. NIST-approved: ML-KEM (formerly CRYSTALS-Kyber).

```typescript
class Poly {
  coeffs: number[];   // in Z_q
  add(other), sub(other), mul(other): Poly    // in Z_q[x]/(x^n + 1)
}
```

The toy implementation here uses small q and noise distributions. Real Kyber uses n=256, q=3329, centered binomial noise.

### Hash-based commitments

```
commit(secret) = SHA-256(secret)
verify(commitment, secret) = commitment === SHA-256(secret)
```

Binding: cannot find a different secret with the same commitment (requires SHA-256 collision). Hiding: doesn't reveal the secret (preimage resistance).

### Quantum-safe PRNG

`HashChainPRNG` uses HMAC-SHA-256 with periodic state refresh. Quantum-safe because Grover only halves output.

For seeds: use `crypto.getRandomValues(32)` — true randomness from the OS, even on quantum systems (the OS RNG is hardware).

## Limitations & caveats

| Primitive | Caveat |
|-----------|--------|
| WOTS-OTS | One-time use only. Reuse leaks the secret. |
| PQ signature | Total signatures = number of OTS keys in tree. |
| Toy Ring-LWE | Not secure — small parameters, no NTT optimization. Use ML-KEM. |
| Merkle tree | Memory grows with leaves; for large trees use a sparse Merkle tree. |

For production, use NIST-standardized implementations:
- **ML-DSA** (Dilithium) — lattice-based signature
- **ML-KEM** (Kyber) — lattice-based KEM
- **SLH-DSA** (SPHINCS+) — hash-based signature
- **FALCON** — lattice-based signature (compact)

This module is for substrate integration and education, not production signing.

## License

MIT.
