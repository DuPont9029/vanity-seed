// BIP39 mnemonic -> m/44'/60'/0'/0/0 -> Ethereum address, on GPU.
// The same source compiles as plain C (CPU_TEST) to validate the crypto
// against the Python reference implementation.

#if defined(__CUDACC__)
#define DEV __device__
#define CONSTMEM __constant__
#else
#define DEV static
#define CONSTMEM static const
#endif

typedef unsigned char u8;
typedef unsigned int u32;
typedef unsigned long long u64;

// ============================================================== SHA-512
CONSTMEM u64 K512[80] = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
    0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL};

CONSTMEM u64 IV512[8] = {
    0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL, 0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
    0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL, 0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL};

#define ROTR64(x, n) (((x) >> (n)) | ((x) << (64 - (n))))
#define ROTL64(x, n) (((x) << (n)) | ((x) >> (64 - (n))))

DEV void sha512_compress(u64 st[8], const u64 m[16]) {
  u64 W[16];
#pragma unroll
  for (int i = 0; i < 16; i++) W[i] = m[i];
  u64 a = st[0], b = st[1], c = st[2], d = st[3], e = st[4], f = st[5], g = st[6], h = st[7];
#pragma unroll
  for (int i = 0; i < 80; i++) {
    u64 wi;
    if (i < 16) {
      wi = W[i];
    } else {
      u64 w15 = W[(i - 15) & 15], w2 = W[(i - 2) & 15];
      u64 s0 = ROTR64(w15, 1) ^ ROTR64(w15, 8) ^ (w15 >> 7);
      u64 s1 = ROTR64(w2, 19) ^ ROTR64(w2, 61) ^ (w2 >> 6);
      wi = W[i & 15] = W[i & 15] + s0 + W[(i - 7) & 15] + s1;
    }
    u64 S1 = ROTR64(e, 14) ^ ROTR64(e, 18) ^ ROTR64(e, 41);
    u64 ch = (e & f) ^ (~e & g);
    u64 t1 = h + S1 + ch + K512[i] + wi;
    u64 S0 = ROTR64(a, 28) ^ ROTR64(a, 34) ^ ROTR64(a, 39);
    u64 mj = (a & b) ^ (a & c) ^ (b & c);
    u64 t2 = S0 + mj;
    h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
  }
  st[0] += a; st[1] += b; st[2] += c; st[3] += d;
  st[4] += e; st[5] += f; st[6] += g; st[7] += h;
}

// key: up to 128 bytes
DEV void hmac_prep(const u8* key, int klen, u64 is[8], u64 os[8]) {
  u64 bi[16], bo[16];
  for (int i = 0; i < 16; i++) {
    u64 kw = 0;
    for (int j = 0; j < 8; j++) {
      int idx = i * 8 + j;
      kw = (kw << 8) | (u64)(idx < klen ? key[idx] : 0);
    }
    bi[i] = kw ^ 0x3636363636363636ULL;
    bo[i] = kw ^ 0x5c5c5c5c5c5c5c5cULL;
  }
  for (int i = 0; i < 8; i++) { is[i] = IV512[i]; os[i] = IV512[i]; }
  sha512_compress(is, bi);
  sha512_compress(os, bo);
}

// msg: up to 111 bytes
DEV void hmac_msg(const u64 is[8], const u64 os[8], const u8* msg, int mlen, u64 out[8]) {
  u64 blk[16];
  for (int i = 0; i < 16; i++) blk[i] = 0;
  for (int i = 0; i < mlen; i++) blk[i >> 3] |= (u64)msg[i] << (56 - 8 * (i & 7));
  blk[mlen >> 3] |= (u64)0x80 << (56 - 8 * (mlen & 7));
  blk[15] = (u64)(128 + mlen) * 8;
  u64 st[8];
  for (int i = 0; i < 8; i++) st[i] = is[i];
  sha512_compress(st, blk);
  for (int i = 0; i < 8; i++) blk[i] = st[i];
  blk[8] = 0x8000000000000000ULL;
  for (int i = 9; i < 15; i++) blk[i] = 0;
  blk[15] = (128 + 64) * 8;
  for (int i = 0; i < 8; i++) out[i] = os[i];
  sha512_compress(out, blk);
}

DEV void words_to_bytes(const u64* w, int nwords, u8* out) {
  for (int i = 0; i < nwords; i++)
    for (int j = 0; j < 8; j++) out[i * 8 + j] = (u8)(w[i] >> (56 - 8 * j));
}

// ============================================================== SHA-256 (checksum only)
CONSTMEM u32 K256[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

#define ROTR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

// returns first byte of SHA-256(16-byte entropy given as two big-endian u64)
DEV u32 sha256_first_byte(u64 hi, u64 lo) {
  u32 W[16];
  W[0] = (u32)(hi >> 32); W[1] = (u32)hi; W[2] = (u32)(lo >> 32); W[3] = (u32)lo;
  W[4] = 0x80000000u;
  for (int i = 5; i < 15; i++) W[i] = 0;
  W[15] = 128;
  u32 a = 0x6a09e667, b = 0xbb67ae85, c = 0x3c6ef372, d = 0xa54ff53a;
  u32 e = 0x510e527f, f = 0x9b05688c, g = 0x1f83d9ab, h = 0x5be0cd19;
#pragma unroll
  for (int i = 0; i < 64; i++) {
    u32 wi;
    if (i < 16) {
      wi = W[i];
    } else {
      u32 w15 = W[(i - 15) & 15], w2 = W[(i - 2) & 15];
      u32 s0 = ROTR32(w15, 7) ^ ROTR32(w15, 18) ^ (w15 >> 3);
      u32 s1 = ROTR32(w2, 17) ^ ROTR32(w2, 19) ^ (w2 >> 10);
      wi = W[i & 15] = W[i & 15] + s0 + W[(i - 7) & 15] + s1;
    }
    u32 S1 = ROTR32(e, 6) ^ ROTR32(e, 11) ^ ROTR32(e, 25);
    u32 ch = (e & f) ^ (~e & g);
    u32 t1 = h + S1 + ch + K256[i] + wi;
    u32 S0 = ROTR32(a, 2) ^ ROTR32(a, 13) ^ ROTR32(a, 22);
    u32 mj = (a & b) ^ (a & c) ^ (b & c);
    u32 t2 = S0 + mj;
    h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
  }
  return (0x6a09e667u + a) >> 24;
}

// ============================================================== Keccak-256
CONSTMEM u64 KRC[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL, 0x8000000080008000ULL,
    0x000000000000808bULL, 0x0000000080000001ULL, 0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008aULL, 0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL, 0x000000000000800aULL, 0x800000008000000aULL,
    0x8000000080008081ULL, 0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL};
CONSTMEM int KROT[24] = {1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
                         27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44};
CONSTMEM int KPI[24] = {10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
                        15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1};

DEV void keccakf(u64 st[25]) {
  u64 bc[5], t;
  for (int r = 0; r < 24; r++) {
#pragma unroll
    for (int i = 0; i < 5; i++) bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];
#pragma unroll
    for (int i = 0; i < 5; i++) {
      t = bc[(i + 4) % 5] ^ ROTL64(bc[(i + 1) % 5], 1);
#pragma unroll
      for (int j = 0; j < 25; j += 5) st[j + i] ^= t;
    }
    t = st[1];
#pragma unroll
    for (int i = 0; i < 24; i++) {
      int j = KPI[i];
      u64 tmp = st[j];
      st[j] = ROTL64(t, KROT[i]);
      t = tmp;
    }
#pragma unroll
    for (int j = 0; j < 25; j += 5) {
#pragma unroll
      for (int i = 0; i < 5; i++) bc[i] = st[j + i];
#pragma unroll
      for (int i = 0; i < 5; i++) st[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
    }
    st[0] ^= KRC[r];
  }
}

// ============================================================== secp256k1 field (8x32 LE limbs)
DEV void fe_copy(u32 r[8], const u32 a[8]) { for (int i = 0; i < 8; i++) r[i] = a[i]; }

// r = t + 0x1000003D1 if that overflows (i.e. t >= p) or force
DEV void fe_final(u32 r[8], const u32 t[8], u32 force) {
  u32 u[8];
  u64 c = (u64)t[0] + 0x3D1u;
  u[0] = (u32)c; c >>= 32;
  c += (u64)t[1] + 1u;
  u[1] = (u32)c; c >>= 32;
  for (int i = 2; i < 8; i++) { c += t[i]; u[i] = (u32)c; c >>= 32; }
  u32 sel = (u32)c | force;
  for (int i = 0; i < 8; i++) r[i] = sel ? u[i] : t[i];
}

DEV void fe_add(u32 r[8], const u32 a[8], const u32 b[8]) {
  u32 t[8];
  u64 c = 0;
  for (int i = 0; i < 8; i++) { c += (u64)a[i] + b[i]; t[i] = (u32)c; c >>= 32; }
  fe_final(r, t, (u32)c);
}

DEV void fe_sub(u32 r[8], const u32 a[8], const u32 b[8]) {
  u32 t[8];
  long long br = 0;
  for (int i = 0; i < 8; i++) {
    long long d = (long long)a[i] - b[i] + br;
    t[i] = (u32)d;
    br = d >> 32;  // 0 or -1
  }
  if (br) {  // t + p  ==  t - 0x1000003D1 (mod 2^256)
    long long d = (long long)t[0] - 0x3D1;
    t[0] = (u32)d; br = d >> 32;
    d = (long long)t[1] - 1 + br;
    t[1] = (u32)d; br = d >> 32;
    for (int i = 2; i < 8; i++) { d = (long long)t[i] + br; t[i] = (u32)d; br = d >> 32; }
  }
  fe_copy(r, t);
}

DEV void fe_mul(u32 r[8], const u32 a[8], const u32 b[8]) {
  u32 w[16];
  for (int i = 0; i < 16; i++) w[i] = 0;
  for (int i = 0; i < 8; i++) {
    u64 c = 0;
    for (int j = 0; j < 8; j++) {
      c += (u64)a[i] * b[j] + w[i + j];
      w[i + j] = (u32)c;
      c >>= 32;
    }
    w[i + 8] = (u32)c;
  }
  // reduce: hi * 2^256 == hi * (2^32 + 977)
  u32 t[8];
  u64 c = 0;
  for (int k = 0; k < 8; k++) {
    c += (u64)w[k] + (u64)w[8 + k] * 977u + (k ? (u64)w[7 + k] : 0);
    t[k] = (u32)c;
    c >>= 32;
  }
  c += w[15];  // top value T (< 2^34)
  u64 T = c;
  u64 lo = (T & 0xffffffffULL) * 977u;
  u64 hi977 = (T >> 32) * 977u;
  u64 d = (u64)t[0] + (lo & 0xffffffffULL);
  t[0] = (u32)d; d >>= 32;
  d += (u64)t[1] + (lo >> 32) + hi977 + (T & 0xffffffffULL);
  t[1] = (u32)d; d >>= 32;
  d += (u64)t[2] + (T >> 32);
  t[2] = (u32)d; d >>= 32;
  for (int k = 3; k < 8; k++) { d += t[k]; t[k] = (u32)d; d >>= 32; }
  if (d) {  // value is 2^256 + small t: add 0x1000003D1 (no further overflow)
    u64 e = (u64)t[0] + 0x3D1u;
    t[0] = (u32)e; e >>= 32;
    e += (u64)t[1] + 1u;
    t[1] = (u32)e; e >>= 32;
    for (int k = 2; k < 8; k++) { e += t[k]; t[k] = (u32)e; e >>= 32; }
  }
  fe_final(r, t, 0);
}

DEV void fe_sqr(u32 r[8], const u32 a[8]) { fe_mul(r, a, a); }

CONSTMEM u32 P_MINUS_2[8] = {0xFFFFFC2Du, 0xFFFFFFFEu, 0xFFFFFFFFu, 0xFFFFFFFFu,
                             0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu};

DEV void fe_inv(u32 r[8], const u32 a[8]) {
  u32 x[8];
  for (int i = 0; i < 8; i++) x[i] = 0;
  x[0] = 1;
  for (int bit = 255; bit >= 0; bit--) {
    fe_sqr(x, x);
    if ((P_MINUS_2[bit >> 5] >> (bit & 31)) & 1) fe_mul(x, x, a);
  }
  fe_copy(r, x);
}

// Jacobian (X,Y,Z) += affine (x2,y2). Assumes points distinct and non-infinite.
DEV void pt_madd(u32 X[8], u32 Y[8], u32 Z[8], const u32 x2[8], const u32 y2[8]) {
  u32 z2[8], u2[8], s2[8], H[8], R[8], H2[8], H3[8], V[8], t[8], t2[8];
  fe_sqr(z2, Z);
  fe_mul(u2, x2, z2);
  fe_mul(t, z2, Z);
  fe_mul(s2, y2, t);
  fe_sub(H, u2, X);
  fe_sub(R, s2, Y);
  fe_sqr(H2, H);
  fe_mul(H3, H2, H);
  fe_mul(V, X, H2);
  fe_sqr(t, R);
  fe_sub(t, t, H3);
  fe_sub(t, t, V);
  fe_sub(t, t, V);  // X3
  fe_sub(t2, V, t);
  fe_mul(t2, R, t2);
  fe_mul(V, Y, H3);
  fe_sub(Y, t2, V);  // Y3
  fe_mul(Z, Z, H);   // Z3
  fe_copy(X, t);
}

// table[(i*16+d)*16 + 0..7] = x, +8..15 = y  of  d * 16^i * G
DEV void mul_g(const u32 k[8], const u32* table, u32 X[8], u32 Y[8], u32 Z[8]) {
  int started = 0;
  for (int i = 0; i < 64; i++) {
    u32 d = (k[i >> 3] >> ((i & 7) * 4)) & 15u;
    if (!d) continue;
    const u32* pt = table + (i * 16 + d) * 16;
    if (!started) {
      for (int j = 0; j < 8; j++) { X[j] = pt[j]; Y[j] = pt[8 + j]; Z[j] = 0; }
      Z[0] = 1;
      started = 1;
    } else {
      pt_madd(X, Y, Z, pt, pt + 8);
    }
  }
}

DEV void to_affine(u32 x[8], u32 y[8], const u32 X[8], const u32 Y[8], const u32 Z[8]) {
  u32 zi[8], zi2[8], zi3[8];
  fe_inv(zi, Z);
  fe_sqr(zi2, zi);
  fe_mul(zi3, zi2, zi);
  fe_mul(x, X, zi2);
  fe_mul(y, Y, zi3);
}

// ============================================================== scalars mod n
CONSTMEM u32 NORD[8] = {0xD0364141u, 0xBFD25E8Cu, 0xAF48A03Bu, 0xBAAEDCE6u,
                        0xFFFFFFFEu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu};

DEV int sc_geq_n(const u32 a[8]) {
  for (int i = 7; i >= 0; i--) {
    if (a[i] > NORD[i]) return 1;
    if (a[i] < NORD[i]) return 0;
  }
  return 1;
}

DEV void sc_sub_n(u32 a[8]) {
  long long br = 0;
  for (int i = 0; i < 8; i++) {
    long long d = (long long)a[i] - NORD[i] + br;
    a[i] = (u32)d;
    br = d >> 32;
  }
}

DEV void sc_add(u32 r[8], const u32 a[8], const u32 b[8]) {
  u64 c = 0;
  for (int i = 0; i < 8; i++) { c += (u64)a[i] + b[i]; r[i] = (u32)c; c >>= 32; }
  if (c || sc_geq_n(r)) sc_sub_n(r);
}

// 4 big-endian u64 words -> 8 LE u32 limbs
DEV void be4_to_limbs(const u64 w[4], u32 r[8]) {
  for (int j = 0; j < 4; j++) {
    r[2 * j] = (u32)w[3 - j];
    r[2 * j + 1] = (u32)(w[3 - j] >> 32);
  }
}

DEV void limbs_to_be(const u32 a[8], u8 out[32]) {
  for (int i = 0; i < 8; i++) {
    u32 v = a[7 - i];
    out[4 * i] = (u8)(v >> 24); out[4 * i + 1] = (u8)(v >> 16);
    out[4 * i + 2] = (u8)(v >> 8); out[4 * i + 3] = (u8)v;
  }
}

// ============================================================== full pipeline
DEV int build_mnemonic(u64 hi, u64 lo, const u8* words, const u8* wlen, u8 pw[128]) {
  u32 cs = sha256_first_byte(hi, lo) >> 4;
  int pos = 0;
  for (int i = 0; i < 128; i++) pw[i] = 0;
  for (int w = 0; w < 12; w++) {
    u32 idx = 0;
    for (int b = 0; b < 11; b++) {
      int bit = w * 11 + b;
      u32 v;
      if (bit < 64) v = (u32)(hi >> (63 - bit)) & 1u;
      else if (bit < 128) v = (u32)(lo >> (127 - bit)) & 1u;
      else v = (cs >> (131 - bit)) & 1u;
      idx = (idx << 1) | v;
    }
    if (w) pw[pos++] = ' ';
    int L = wlen[idx];
    for (int j = 0; j < L; j++) pw[pos++] = words[idx * 8 + j];
  }
  return pos;
}

DEV void ent_to_address(u64 hi, u64 lo, const u8* words, const u8* wlen,
                        const u32* table, u8 addr[20]) {
  u8 pw[128];
  int pwlen = build_mnemonic(hi, lo, words, wlen, pw);

  // ---- PBKDF2-HMAC-SHA512(mnemonic, "mnemonic", 2048) -> 64 bytes
  u64 is[8], os[8], U[8], T[8], blk[16];
  hmac_prep(pw, pwlen, is, os);
  const u8 salt[12] = {'m', 'n', 'e', 'm', 'o', 'n', 'i', 'c', 0, 0, 0, 1};
  hmac_msg(is, os, salt, 12, U);
  for (int i = 0; i < 8; i++) T[i] = U[i];
  for (int it = 1; it < 2048; it++) {
    for (int i = 0; i < 8; i++) blk[i] = U[i];
    blk[8] = 0x8000000000000000ULL;
    for (int i = 9; i < 15; i++) blk[i] = 0;
    blk[15] = (128 + 64) * 8;
    u64 st[8];
    for (int i = 0; i < 8; i++) st[i] = is[i];
    sha512_compress(st, blk);
    for (int i = 0; i < 8; i++) blk[i] = st[i];
    for (int i = 0; i < 8; i++) U[i] = os[i];
    sha512_compress(U, blk);
    for (int i = 0; i < 8; i++) T[i] ^= U[i];
  }

  // ---- BIP32 master
  u8 buf[64];
  u64 I[8];
  words_to_bytes(T, 8, buf);
  const u8 btc[12] = {'B', 'i', 't', 'c', 'o', 'i', 'n', ' ', 's', 'e', 'e', 'd'};
  hmac_prep(btc, 12, is, os);
  hmac_msg(is, os, buf, 64, I);
  u32 k[8], il[8];
  be4_to_limbs(I, k);
  u8 chain[32];
  words_to_bytes(I + 4, 4, chain);

  // ---- hardened 44' 60' 0'
  const u32 hidx[3] = {0x8000002Cu, 0x8000003Cu, 0x80000000u};
  u8 msg[37];
  for (int lvl = 0; lvl < 3; lvl++) {
    msg[0] = 0;
    limbs_to_be(k, msg + 1);
    msg[33] = (u8)(hidx[lvl] >> 24); msg[34] = (u8)(hidx[lvl] >> 16);
    msg[35] = (u8)(hidx[lvl] >> 8); msg[36] = (u8)hidx[lvl];
    hmac_prep(chain, 32, is, os);
    hmac_msg(is, os, msg, 37, I);
    be4_to_limbs(I, il);
    sc_add(k, k, il);
    words_to_bytes(I + 4, 4, chain);
  }

  // ---- pub = k*G
  u32 X[8], Y[8], Z[8], px[8], py[8];
  mul_g(k, table, X, Y, Z);
  to_affine(px, py, X, Y, Z);

  // ---- non-hardened 0 / 0 : pub' = pub + IL*G
  for (int lvl = 0; lvl < 2; lvl++) {
    msg[0] = (u8)(2 + (py[0] & 1));
    limbs_to_be(px, msg + 1);
    msg[33] = msg[34] = msg[35] = msg[36] = 0;
    hmac_prep(chain, 32, is, os);
    hmac_msg(is, os, msg, 37, I);
    be4_to_limbs(I, il);
    words_to_bytes(I + 4, 4, chain);
    mul_g(il, table, X, Y, Z);
    pt_madd(X, Y, Z, px, py);
    to_affine(px, py, X, Y, Z);
  }

  // ---- keccak256(x || y)
  u8 xy[64];
  limbs_to_be(px, xy);
  limbs_to_be(py, xy + 32);
  u64 st[25];
  for (int i = 0; i < 25; i++) st[i] = 0;
  for (int i = 0; i < 8; i++) {
    u64 v = 0;
    for (int j = 7; j >= 0; j--) v = (v << 8) | xy[i * 8 + j];
    st[i] = v;
  }
  st[8] ^= 0x01ULL;
  st[16] ^= 0x8000000000000000ULL;
  keccakf(st);
  for (int i = 0; i < 20; i++) {
    int b = 12 + i;
    addr[i] = (u8)(st[b >> 3] >> (8 * (b & 7)));
  }
}

// ============================================================== kernels
#if defined(__CUDACC__)
extern "C" __global__ void derive(const u8* words, const u8* wlen, const u32* table,
                                  const u64* ents, u32 n, u8* out) {
  u32 gid = blockIdx.x * blockDim.x + threadIdx.x;
  if (gid >= n) return;
  ent_to_address(ents[2 * gid], ents[2 * gid + 1], words, wlen, table, out + 20 * gid);
}

extern "C" __global__ void search(const u8* words, const u8* wlen, const u32* table,
                                  u64 base_hi, u64 base_lo, u32 n,
                                  const u8* pat, u32 plen, u32 slen,
                                  u32* hit_count, u64* hits, u32 max_hits) {
  u32 gid = blockIdx.x * blockDim.x + threadIdx.x;
  if (gid >= n) return;
  u64 lo = base_lo + gid;
  u64 hi = base_hi + (lo < base_lo ? 1 : 0);
  u8 addr[20];
  ent_to_address(hi, lo, words, wlen, table, addr);
  // pat[i] = 0..15 nibble esatto, 16 = qualsiasi cifra decimale (0-9)
  for (u32 i = 0; i < plen; i++) {
    u32 nib = (addr[i >> 1] >> ((i & 1) ? 0 : 4)) & 15u;
    u32 p = pat[i];
    if (p == 16 ? nib > 9 : nib != p) return;
  }
  for (u32 s = 0; s < slen; s++) {
    u32 i = 40 - slen + s;
    u32 nib = (addr[i >> 1] >> ((i & 1) ? 0 : 4)) & 15u;
    u32 p = pat[plen + s];
    if (p == 16 ? nib > 9 : nib != p) return;
  }
  u32 slot = atomicAdd(hit_count, 1u);
  if (slot < max_hits) { hits[2 * slot] = hi; hits[2 * slot + 1] = lo; }
}
#endif

// ============================================================== CPU harness
#if defined(CPU_TEST)
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
// usage: ./harness table.bin words.bin < entropies_hex > addresses_hex
int main(int argc, char** argv) {
  static u32 table[64 * 16 * 16];
  static u8 words[2048 * 8], wlen[2048];
  FILE* f = fopen(argv[1], "rb");
  if (fread(table, 4, 64 * 16 * 16, f) != 64 * 16 * 16) return 1;
  fclose(f);
  f = fopen(argv[2], "rb");
  if (fread(words, 1, 2048 * 8, f) != 2048 * 8) return 1;
  if (fread(wlen, 1, 2048, f) != 2048) return 1;
  fclose(f);
  char line[128];
  while (fgets(line, sizeof line, stdin)) {
    u64 hi = strtoull(strndup(line, 16), 0, 16), lo = strtoull(line + 16, 0, 16);
    u8 a[20];
    ent_to_address(hi, lo, words, wlen, table, a);
    for (int i = 0; i < 20; i++) printf("%02x", a[i]);
    printf("\n");
  }
  return 0;
}
#endif
