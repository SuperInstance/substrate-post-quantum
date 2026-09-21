/**
 * substrate-post-quantum: Post-quantum cryptographic primitives.
 *
 * Math notes:
 *
 *   We implement two post-quantum primitives suitable for the substrate:
 *
 *   1. Hash-based signature (XMSS-style Merkle signature scheme).
 *      Security: relies only on hash function collision/preimage resistance.
 *      Quantum-safe because Grover's algorithm only gives √ speedup on hash search.
 *
 *   2. Lattice-based key encapsulation (toy Ring-LWE).
 *      Security: relies on hardness of Learning With Errors over rings.
 *      Quantum-safe: best known quantum attack is exponential.
 *
 *   3. Hash-based commitment scheme (commitment = H(secret), reveal = secret).
 *
 *   Both primitives are toy/reference. For production, use NIST-standardized
 *   implementations: ML-DSA (Dilithium), ML-KEM (Kyber), SPHINCS+, FALCON.
 *
 *   The point of this module is that the substrate's witness-log + cell hash
 *   algebra *can* be hardened against quantum adversaries with simple
 *   constructions, without depending on RSA/ECC.
 */

import { createHash, randomBytes, createHmac } from 'node:crypto';

/** Hex helpers */
function toHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}
function fromHex(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return out;
}
function sha256(data: Uint8Array | string): Uint8Array {
  return new Uint8Array(createHash('sha256').update(data).digest());
}
function sha512(data: Uint8Array | string): Uint8Array {
  return new Uint8Array(createHash('sha512').update(data).digest());
}
function hmacSha256(key: Uint8Array | string, data: Uint8Array | string): Uint8Array {
  return new Uint8Array(createHmac('sha256', key).update(data).digest());
}

/** ============== Hash-based signature (Merkle signature scheme) ============== */

/** A Merkle tree node. */
export interface MerkleNode {
  hash: Uint8Array;
  left?: MerkleNode;
  right?: MerkleNode;
}

/** Build a Merkle tree from a list of leaf hashes. */
export function buildMerkleTree(leaves: Uint8Array[]): MerkleNode {
  if (leaves.length === 0) throw new Error('buildMerkleTree: no leaves');
  if (leaves.length === 1) {
    return { hash: leaves[0] };
  }
  // Pad to power of 2
  let level: MerkleNode[] = leaves.map(h => ({ hash: h }));
  while (level.length > 1) {
    if (level.length % 2 !== 0) {
      level.push({ hash: sha256(Buffer.from('padding')) });
    }
    const next: MerkleNode[] = [];
    for (let i = 0; i < level.length; i += 2) {
      const combined = new Uint8Array(64);
      combined.set(level[i].hash, 0);
      combined.set(level[i + 1].hash, 32);
      next.push({ hash: sha256(combined), left: level[i], right: level[i + 1] });
    }
    level = next;
  }
  return level[0];
}

/** Get the Merkle proof (path) for a leaf at index.
 *  Returns siblings from leaf level up, in the order they should be combined during verification.
 *  Algorithm: walk down from root to leaf, at each level push the sibling
 *  at the appropriate position, then descend. Reverse at end. */
export function merkleProof(root: MerkleNode, index: number): Uint8Array[] {
  if (!root.left && !root.right) return [];

  // Compute tree depth from number of leaves (caller passed in via root structure)
  // We track the current level's nodes and the position at each level.
  const reverse: Uint8Array[] = [];
  let level: MerkleNode[] = [root];
  let posInLevel = 0;  // position in current level (always 0 at root)

  while (true) {
    const node = level[posInLevel];
    if (!node) throw new Error('merkleProof: index out of range');

    // Determine children
    const children: MerkleNode[] = node.left && node.right
      ? [node.left, node.right]
      : [];
    if (children.length === 0) break;  // reached a leaf

    // Determine which child contains the leaf at the original index
    // For N leaves, leaf index = posInLevel * (N / currentLevel.length) + offset
    // Simpler: track which leaf we're after by descending.
    // We need to know if our target leaf is in left or right subtree.
    // The target leaf index at the children level is determined by bit at depth.
    // ... let's just use the leaf index directly.
    break;  // we'll redo
  }

  // Actually, a cleaner approach: build the level arrays explicitly, then walk.
  return merkleProofFromLevels(root, index);
}

/** Helper: get level arrays from root down. */
function getLevels(root: MerkleNode): MerkleNode[][] {
  const levels: MerkleNode[][] = [];
  let current: MerkleNode[] = [root];
  levels.push(current);
  while (true) {
    const next: MerkleNode[] = [];
    let allLeaves = true;
    for (const node of current) {
      if (node.left && node.right) {
        next.push(node.left, node.right);
        allLeaves = false;
      }
    }
    if (allLeaves) break;
    levels.push(next);
    current = next;
  }
  return levels;
}

/** Compute Merkle proof given the level arrays and leaf index.
 *  Returns siblings in order from leaf level up. */
function merkleProofFromLevels(root: MerkleNode, index: number): Uint8Array[] {
  if (!root.left && !root.right) return [];
  const levels = getLevels(root);
  const path: Uint8Array[] = [];
  // Walk from leaf level up to root level
  // Leaf is at the last level, at position = index
  let pos = index;
  for (let levelIdx = levels.length - 1; levelIdx >= 1; levelIdx--) {
    const level = levels[levelIdx];
    if (pos < 0 || pos >= level.length) throw new Error('merkleProof: index out of range');
    const siblingPos = pos ^ 1;  // XOR 1 flips the last bit
    if (siblingPos >= level.length) throw new Error('merkleProof: sibling out of range (padded tree?)');
    const sibling = level[siblingPos];
    path.push(sibling.hash);
    pos = Math.floor(pos / 2);
  }
  return path;
}

/** Verify a Merkle proof.
 *  path = [sibling_at_leaf_level, sibling_at_parent_level, ..., sibling_at_root_level]
 *  Verification: combine leaf with first sibling, then combine result with next sibling, etc. */
export function verifyMerkleProof(root: Uint8Array, leaf: Uint8Array, index: number, path: Uint8Array[]): boolean {
  let h = leaf;
  let idx = index;
  for (const sibling of path) {
    const combined = new Uint8Array(64);
    if (idx % 2 === 0) {
      combined.set(h, 0);
      combined.set(sibling, 32);
    } else {
      combined.set(sibling, 0);
      combined.set(h, 32);
    }
    h = sha256(combined);
    idx = Math.floor(idx / 2);
  }
  if (h.length !== root.length) return false;
  for (let i = 0; i < h.length; i++) {
    if (h[i] !== root[i]) return false;
  }
  return true;
}

/** One-Time Signature (WOTS-style, simplified).
 *  Each signature chunk i is a hash chain: sk hashed (MAX - count_i) times,
 *  where count_i is derived from the message digest. Verification hashes
 *  signature[i] count_i times to recover pk[i].
 *
 *  Security: relies on preimage resistance of SHA-256 (quantum-safe modulo Grover). */
export interface OTSKeypair {
  sk: Uint8Array;
  pk: Uint8Array[];
  /** max hashes per chunk */
  maxHashes: number;
}

export function otsGenerate(n: number = 32, maxHashes: number = 256): OTSKeypair {
  const sk = randomBytes(32);
  const pk: Uint8Array[] = [];
  for (let i = 0; i < n; i++) {
    let cur = sk;
    for (let j = 0; j < maxHashes; j++) cur = sha256(cur);
    // Each pk slot uses a different starting chain (offset by i)
    for (let j = 0; j < i; j++) cur = sha256(cur);
    pk.push(cur);
  }
  return { sk, pk, maxHashes };
}

/** Extract the count for chunk i from the message digest.
 *  Use the i-th byte of the digest as the count (range 0..255). */
function extractCount(messageDigest: Uint8Array, i: number, maxHashes: number): number {
  const byte = i < messageDigest.length ? messageDigest[i] : 0;
  // Reduce to range [0, maxHashes)
  return byte % maxHashes;
}

/** Sign a message digest using a WOTS-like one-time signature. */
export function otsSign(sk: Uint8Array, messageDigest: Uint8Array, n: number = 32, maxHashes: number = 256): Uint8Array[] {
  const sig: Uint8Array[] = [];
  for (let i = 0; i < n; i++) {
    const count = extractCount(messageDigest, i, maxHashes);
    // Hash chain: sk hashed (maxHashes + i - count) times
    let cur = sk;
    const totalHashes = maxHashes + i - count;
    for (let j = 0; j < totalHashes; j++) cur = sha256(cur);
    sig.push(cur);
  }
  return sig;
}

/** Verify a WOTS signature against a public key and message digest. */
export function otsVerify(pk: Uint8Array[], messageDigest: Uint8Array, signature: Uint8Array[], maxHashes: number = 256): boolean {
  if (pk.length !== signature.length) return false;
  for (let i = 0; i < pk.length; i++) {
    const count = extractCount(messageDigest, i, maxHashes);
    // Hash signature[i] count times to recover pk[i]
    let h = signature[i];
    for (let c = 0; c < count; c++) h = sha256(h);
    if (h.length !== pk[i].length) return false;
    for (let j = 0; j < h.length; j++) {
      if (h[j] !== pk[i][j]) return false;
    }
  }
  return true;
}

/** ============== Lattice-based KEM (toy Ring-LWE) ============== */

/** Polynomial in Z_q[x]/(x^n + 1). Coefficients mod q. */
export class Poly {
  coeffs: number[];
  n: number;
  q: number;

  constructor(n: number, q: number, coeffs?: number[]) {
    this.n = n;
    this.q = q;
    this.coeffs = coeffs ?? new Array(n).fill(0);
    for (let i = 0; i < n; i++) {
      this.coeffs[i] = ((this.coeffs[i] % q) + q) % q;
    }
  }

  static zero(n: number, q: number): Poly {
    return new Poly(n, q);
  }

  static random(n: number, q: number, range: number = 3): Poly {
    // Small coefficients in {-range, ..., range}
    const coeffs = new Array(n);
    for (let i = 0; i < n; i++) {
      coeffs[i] = Math.floor(Math.random() * (2 * range + 1)) - range;
    }
    return new Poly(n, q, coeffs);
  }

  add(other: Poly): Poly {
    const c = new Array(this.n);
    for (let i = 0; i < this.n; i++) {
      c[i] = this.coeffs[i] + other.coeffs[i];
    }
    return new Poly(this.n, this.q, c);
  }

  sub(other: Poly): Poly {
    const c = new Array(this.n);
    for (let i = 0; i < this.n; i++) {
      c[i] = this.coeffs[i] - other.coeffs[i];
    }
    return new Poly(this.n, this.q, c);
  }

  /** Multiply two polynomials in Z_q[x]/(x^n + 1). */
  mul(other: Poly): Poly {
    const c = new Array(this.n).fill(0);
    for (let i = 0; i < this.n; i++) {
      for (let j = 0; j < this.n; j++) {
        let prod = this.coeffs[i] * other.coeffs[j];
        const k = (i + j) % this.n;
        // x^n = -1 in the quotient
        if (i + j < this.n) {
          c[k] += prod;
        } else {
          c[k] -= prod;
        }
      }
    }
    return new Poly(this.n, this.q, c);
  }

  /** Sample from the discrete Gaussian distribution (small noise). */
  static gaussian(n: number, q: number, sigma: number = 2): Poly {
    const coeffs = new Array(n);
    for (let i = 0; i < n; i++) {
      // Box-Muller for Gaussian samples
      let u1 = Math.random();
      if (u1 < 1e-15) u1 = 1e-15;
      const u2 = Math.random();
      coeffs[i] = Math.round(Math.sqrt(-2 * Math.log(u1)) * Math.cos(2 * Math.PI * u2) * sigma);
    }
    return new Poly(n, q, coeffs);
  }

  toBytes(): Uint8Array {
    // 2 bytes per coefficient (q < 2^16)
    const out = new Uint8Array(this.n * 2);
    for (let i = 0; i < this.n; i++) {
      out[i * 2] = this.coeffs[i] & 0xff;
      out[i * 2 + 1] = (this.coeffs[i] >> 8) & 0xff;
    }
    return out;
  }

  static fromBytes(bytes: Uint8Array, n: number, q: number): Poly {
    const coeffs = new Array(n);
    for (let i = 0; i < n; i++) {
      coeffs[i] = bytes[i * 2] | (bytes[i * 2 + 1] << 8);
    }
    return new Poly(n, q, coeffs);
  }
}

/** LWE key pair. Toy version, not secure.
 *  pk = (a, b = a*s + e)
 *  sk = s
 *  Encrypt(m): u = a*r + e1, v = b*r + e2 + m
 *  Decrypt(c): m = v - s*u */
export interface LWEKeypair {
  sk: Poly;
  pk: { a: Poly, b: Poly };
}

export function lweGenerate(N: number = 16, q: number = 1024): LWEKeypair {
  const sk = Poly.random(N, q);
  const a = Poly.random(N, q);
  const e = Poly.gaussian(N, q);
  const b = a.mul(sk).add(e);
  return { sk, pk: { a, b } };
}

export function lweEncrypt(pk: { a: Poly, b: Poly }, message: Poly, N: number = 16, q: number = 1024): { u: Poly, v: Poly } {
  const r = Poly.random(N, q);
  const e1 = Poly.gaussian(N, q);
  const e2 = Poly.gaussian(N, q);
  const u = pk.a.mul(r).add(e1);
  const v = pk.b.mul(r).add(e2).add(message);
  return { u, v };
}

export function lweDecrypt(sk: Poly, ct: { u: Poly, v: Poly }): Poly {
  return ct.v.sub(sk.mul(ct.u));
}

/** ============== Hash-based commitment ============== */

export interface Commitment {
  commitment: string;
  secret: string;
}

export function commit(secret: string): Commitment {
  return {
    commitment: toHex(sha256(secret)),
    secret,
  };
}

export function verifyCommitment(commitment: string, secret: string): boolean {
  return commitment === toHex(sha256(secret));
}

/** ============== Hash-based PRNG (quantum-safe for output, not state) ============== */

/** Hash chain: H^n(seed) — forward-secure PRNG.
 *  Quantum note: Grover gives √ speedup so use 2x output bits for security. */
export class HashChainPRNG {
  private state: Uint8Array;
  private count: number = 0;

  constructor(seed: Uint8Array) {
    this.state = sha512(seed);
  }

  next(n: number): Uint8Array {
    const out = new Uint8Array(n);
    let offset = 0;
    while (offset < n) {
      // HMAC the count + state
      const msg = new Uint8Array(this.state.length + 4);
      msg.set(this.state, 0);
      msg[this.state.length] = (this.count >>> 24) & 0xff;
      msg[this.state.length + 1] = (this.count >>> 16) & 0xff;
      msg[this.state.length + 2] = (this.count >>> 8) & 0xff;
      msg[this.state.length + 3] = this.count & 0xff;
      const block = hmacSha256(this.state, msg);
      const take = Math.min(block.length, n - offset);
      out.set(block.subarray(0, take), offset);
      offset += take;
      this.count++;
      // Update state every 256 blocks (HMAC-DRBG style)
      if (this.count % 256 === 0) {
        this.state = new Uint8Array(hmacSha256(this.state, new Uint8Array([0])));
      }
    }
    return out;
  }
}

/** ============== Higher-level: post-quantum signature ============== */

export interface PQKeypair {
  publicKey: { rootHash: Uint8Array, otsPks: Uint8Array[][] };
  privateKey: { otsSks: Uint8Array[], treeLeaves: Uint8Array[] };
}

export function pqGenerate(numOTS: number = 4): PQKeypair {
  const otsSks: Uint8Array[] = [];
  const otsPks: Uint8Array[][] = [];
  const treeLeaves: Uint8Array[] = [];
  for (let i = 0; i < numOTS; i++) {
    const kp = otsGenerate(32);
    otsSks.push(kp.sk);
    otsPks.push(kp.pk);
    // Hash the public key for the Merkle tree leaf
    treeLeaves.push(sha256(Buffer.concat(kp.pk.map(p => Buffer.from(p)))));
  }
  const tree = buildMerkleTree(treeLeaves);
  return {
    publicKey: { rootHash: tree.hash, otsPks },
    privateKey: { otsSks, treeLeaves },
  };
}

export function pqSign(privateKey: PQKeypair['privateKey'], message: Uint8Array, otsIndex: number): {
  signature: Uint8Array[],
  merklePath: Uint8Array[],
  messageDigest: Uint8Array,
  otsIndex: number,
} {
  if (otsIndex >= privateKey.otsSks.length) {
    throw new Error('pqSign: OTS index out of range');
  }
  const messageDigest = sha256(message);
  const signature = otsSign(privateKey.otsSks[otsIndex], messageDigest);
  // Compute Merkle path
  const tree = buildMerkleTree(privateKey.treeLeaves);
  const merklePath = merkleProof(tree, otsIndex);
  return { signature, merklePath, messageDigest, otsIndex };
}

export function pqVerify(publicKey: PQKeypair['publicKey'], message: Uint8Array, sig: {
  signature: Uint8Array[],
  merklePath: Uint8Array[],
  messageDigest: Uint8Array,
  otsIndex: number,
}): boolean {
  // Verify OTS signature — recompute the digest from the message
  const otsPk = publicKey.otsPks[sig.otsIndex];
  if (!otsPk) return false;
  const computedDigest = sha256(message);
  if (!otsVerify(otsPk, computedDigest, sig.signature)) return false;
  // Verify Merkle path
  const leaf = sha256(Buffer.concat(otsPk.map(p => Buffer.from(p))));
  return verifyMerkleProof(publicKey.rootHash, leaf, sig.otsIndex, sig.merklePath);
}

export { toHex, fromHex, sha256, sha512, hmacSha256 };
