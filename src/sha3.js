const MASK_64 = (1n << 64n) - 1n;

const ROUND_CONSTANTS = [
  0x0000000000000001n, 0x0000000000008082n, 0x800000000000808an,
  0x8000000080008000n, 0x000000000000808bn, 0x0000000080000001n,
  0x8000000080008081n, 0x8000000000008009n, 0x000000000000008an,
  0x0000000000000088n, 0x0000000080008009n, 0x000000008000000an,
  0x000000008000808bn, 0x800000000000008bn, 0x8000000000008089n,
  0x8000000000008003n, 0x8000000000008002n, 0x8000000000000080n,
  0x000000000000800an, 0x800000008000000an, 0x8000000080008081n,
  0x8000000000008080n, 0x0000000080000001n, 0x8000000080008008n,
];

const RHO = [
  [0, 36, 3, 41, 18],
  [1, 44, 10, 45, 2],
  [62, 6, 43, 15, 61],
  [28, 55, 25, 21, 56],
  [27, 20, 39, 8, 14],
];

function rotl64(value, shift) {
  const n = BigInt(shift);
  if (n === 0n) return value & MASK_64;
  return ((value << n) | (value >> (64n - n))) & MASK_64;
}

function laneIndex(x, y) {
  return x + 5 * y;
}

function keccakF1600(state) {
  for (const rc of ROUND_CONSTANTS) {
    const c = new Array(5).fill(0n);
    const d = new Array(5).fill(0n);

    for (let x = 0; x < 5; x += 1) {
      c[x] =
        state[laneIndex(x, 0)] ^
        state[laneIndex(x, 1)] ^
        state[laneIndex(x, 2)] ^
        state[laneIndex(x, 3)] ^
        state[laneIndex(x, 4)];
    }

    for (let x = 0; x < 5; x += 1) {
      d[x] = c[(x + 4) % 5] ^ rotl64(c[(x + 1) % 5], 1);
    }

    for (let x = 0; x < 5; x += 1) {
      for (let y = 0; y < 5; y += 1) {
        state[laneIndex(x, y)] = (state[laneIndex(x, y)] ^ d[x]) & MASK_64;
      }
    }

    const b = new Array(25).fill(0n);
    for (let x = 0; x < 5; x += 1) {
      for (let y = 0; y < 5; y += 1) {
        const newX = y;
        const newY = (2 * x + 3 * y) % 5;
        b[laneIndex(newX, newY)] = rotl64(state[laneIndex(x, y)], RHO[x][y]);
      }
    }

    for (let x = 0; x < 5; x += 1) {
      for (let y = 0; y < 5; y += 1) {
        state[laneIndex(x, y)] =
          (b[laneIndex(x, y)] ^
            ((~b[laneIndex((x + 1) % 5, y)] & MASK_64) & b[laneIndex((x + 2) % 5, y)])) &
          MASK_64;
      }
    }

    state[0] = (state[0] ^ rc) & MASK_64;
  }
}

function toBytes(input) {
  if (input instanceof Uint8Array) return input;
  if (typeof input === 'string') return new TextEncoder().encode(input);
  return new Uint8Array(input);
}

export function sha3_256(input) {
  const rate = 136;
  const bytes = toBytes(input);
  const padLen = rate - ((bytes.length + 1) % rate);
  const padded = new Uint8Array(bytes.length + 1 + padLen);
  padded.set(bytes);
  padded[bytes.length] = 0x06;
  padded[padded.length - 1] ^= 0x80;

  const state = new Array(25).fill(0n);

  for (let offset = 0; offset < padded.length; offset += rate) {
    for (let i = 0; i < rate; i += 1) {
      const lane = Math.floor(i / 8);
      const shift = BigInt((i % 8) * 8);
      state[lane] ^= BigInt(padded[offset + i]) << shift;
      state[lane] &= MASK_64;
    }
    keccakF1600(state);
  }

  const out = new Uint8Array(32);
  for (let i = 0; i < out.length; i += 1) {
    const lane = Math.floor(i / 8);
    const shift = BigInt((i % 8) * 8);
    out[i] = Number((state[lane] >> shift) & 0xffn);
  }

  return out;
}

export function bytesToHex(bytes) {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

export function sha3_256_hex(input) {
  return bytesToHex(sha3_256(input));
}
