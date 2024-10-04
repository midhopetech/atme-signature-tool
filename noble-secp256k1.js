/**
 * Copyright 2024 Mid Hope Technologies
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

function hmacDrbg(asynchronous) {
  let v = u8n(fLen);
  let k = u8n(fLen);
  let i = 0;
  const reset = () => {
    v.fill(1);
    k.fill(0);
    i = 0;
  };
  const _e = "drbg: tried 1000 values";
  if (asynchronous) {
    const h = (...b) => etc.hmacSha256Async(k, v, ...b);
    const reseed = async (seed = u8n()) => {
      k = await h(u8n([0]), seed);
      v = await h();
      if (seed.length === 0)
        return;
      k = await h(u8n([1]), seed);
      v = await h();
    };
    const gen = async () => {
      if (i++ >= 1000)
        err(_e);
      v = await h();
      return v;
    };
    return async (seed, pred) => {
      reset();
      await reseed(seed);
      let res = undefined;
      while (!(res = pred(await gen())))
        await reseed();
      reset();
      return res;
    };
  } else {
    const h = (...b) => {
      const f = _hmacSync;
      if (!f)
        err("etc.hmacSha256Sync not set");
      return f(k, v, ...b);
    };
    const reseed = (seed = u8n()) => {
      k = h(u8n([0]), seed);
      v = h();
      if (seed.length === 0)
        return;
      k = h(u8n([1]), seed);
      v = h();
    };
    const gen = () => {
      if (i++ >= 1000)
        err(_e);
      v = h();
      return v;
    };
    return (seed, pred) => {
      reset();
      reseed(seed);
      let res = undefined;
      while (!(res = pred(gen())))
        reseed();
      reset();
      return res;
    };
  }
}
/*! noble-secp256k1 - MIT License (c) 2019 Paul Miller (paulmillr.com) */
var B256 = 2n ** 256n;
var P = B256 - 0x1000003d1n;
var N = B256 - 0x14551231950b75fc4402da1732fc9bebfn;
var Gx = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n;
var Gy = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n;
var CURVE = { p: P, n: N, a: 0n, b: 7n, Gx, Gy };
var fLen = 32;
var crv = (x) => mod(mod(x * x) * x + CURVE.b);
var err = (m = "") => {
  throw new Error(m);
};
var big = (n) => typeof n === "bigint";
var str = (s) => typeof s === "string";
var fe = (n) => big(n) && 0n < n && n < P;
var ge = (n) => big(n) && 0n < n && n < N;
var isu8 = (a) => a instanceof Uint8Array || a != null && typeof a === "object" && a.constructor.name === "Uint8Array";
var au8 = (a, l) => !isu8(a) || typeof l === "number" && l > 0 && a.length !== l ? err("Uint8Array expected") : a;
var u8n = (data) => new Uint8Array(data);
var toU8 = (a, len) => au8(str(a) ? h2b(a) : u8n(au8(a)), len);
var mod = (a, b = P) => {
  let r = a % b;
  return r >= 0n ? r : b + r;
};
var isPoint = (p) => p instanceof Point ? p : err("Point expected");

class Point {
  constructor(px, py, pz) {
    this.px = px;
    this.py = py;
    this.pz = pz;
  }
  static fromAffine(p) {
    return p.x === 0n && p.y === 0n ? Point.ZERO : new Point(p.x, p.y, 1n);
  }
  static fromHex(hex) {
    hex = toU8(hex);
    let p = undefined;
    const head = hex[0], tail = hex.subarray(1);
    const x = slcNum(tail, 0, fLen), len = hex.length;
    if (len === 33 && [2, 3].includes(head)) {
      if (!fe(x))
        err("Point hex invalid: x not FE");
      let y = sqrt(crv(x));
      const isYOdd = (y & 1n) === 1n;
      const headOdd = (head & 1) === 1;
      if (headOdd !== isYOdd)
        y = mod(-y);
      p = new Point(x, y, 1n);
    }
    if (len === 65 && head === 4)
      p = new Point(x, slcNum(tail, fLen, 2 * fLen), 1n);
    return p ? p.ok() : err("Point is not on curve");
  }
  static fromPrivateKey(k) {
    return G.mul(toPriv(k));
  }
  get x() {
    return this.aff().x;
  }
  get y() {
    return this.aff().y;
  }
  equals(other) {
    const { px: X1, py: Y1, pz: Z1 } = this;
    const { px: X2, py: Y2, pz: Z2 } = isPoint(other);
    const X1Z2 = mod(X1 * Z2), X2Z1 = mod(X2 * Z1);
    const Y1Z2 = mod(Y1 * Z2), Y2Z1 = mod(Y2 * Z1);
    return X1Z2 === X2Z1 && Y1Z2 === Y2Z1;
  }
  negate() {
    return new Point(this.px, mod(-this.py), this.pz);
  }
  double() {
    return this.add(this);
  }
  add(other) {
    const { px: X1, py: Y1, pz: Z1 } = this;
    const { px: X2, py: Y2, pz: Z2 } = isPoint(other);
    const { a, b } = CURVE;
    let X3 = 0n, Y3 = 0n, Z3 = 0n;
    const b3 = mod(b * 3n);
    let t0 = mod(X1 * X2), t1 = mod(Y1 * Y2), t2 = mod(Z1 * Z2), t3 = mod(X1 + Y1);
    let t4 = mod(X2 + Y2);
    t3 = mod(t3 * t4);
    t4 = mod(t0 + t1);
    t3 = mod(t3 - t4);
    t4 = mod(X1 + Z1);
    let t5 = mod(X2 + Z2);
    t4 = mod(t4 * t5);
    t5 = mod(t0 + t2);
    t4 = mod(t4 - t5);
    t5 = mod(Y1 + Z1);
    X3 = mod(Y2 + Z2);
    t5 = mod(t5 * X3);
    X3 = mod(t1 + t2);
    t5 = mod(t5 - X3);
    Z3 = mod(a * t4);
    X3 = mod(b3 * t2);
    Z3 = mod(X3 + Z3);
    X3 = mod(t1 - Z3);
    Z3 = mod(t1 + Z3);
    Y3 = mod(X3 * Z3);
    t1 = mod(t0 + t0);
    t1 = mod(t1 + t0);
    t2 = mod(a * t2);
    t4 = mod(b3 * t4);
    t1 = mod(t1 + t2);
    t2 = mod(t0 - t2);
    t2 = mod(a * t2);
    t4 = mod(t4 + t2);
    t0 = mod(t1 * t4);
    Y3 = mod(Y3 + t0);
    t0 = mod(t5 * t4);
    X3 = mod(t3 * X3);
    X3 = mod(X3 - t0);
    t0 = mod(t3 * t1);
    Z3 = mod(t5 * Z3);
    Z3 = mod(Z3 + t0);
    return new Point(X3, Y3, Z3);
  }
  mul(n, safe = true) {
    if (!safe && n === 0n)
      return I;
    if (!ge(n))
      err("invalid scalar");
    if (this.equals(G))
      return wNAF(n).p;
    let p = I, f = G;
    for (let d = this;n > 0n; d = d.double(), n >>= 1n) {
      if (n & 1n)
        p = p.add(d);
      else if (safe)
        f = f.add(d);
    }
    return p;
  }
  mulAddQUns(R, u1, u2) {
    return this.mul(u1, false).add(R.mul(u2, false)).ok();
  }
  toAffine() {
    const { px: x, py: y, pz: z } = this;
    if (this.equals(I))
      return { x: 0n, y: 0n };
    if (z === 1n)
      return { x, y };
    const iz = inv(z);
    if (mod(z * iz) !== 1n)
      err("invalid inverse");
    return { x: mod(x * iz), y: mod(y * iz) };
  }
  assertValidity() {
    const { x, y } = this.aff();
    if (!fe(x) || !fe(y))
      err("Point invalid: x or y");
    return mod(y * y) === crv(x) ? this : err("Point invalid: not on curve");
  }
  multiply(n) {
    return this.mul(n);
  }
  aff() {
    return this.toAffine();
  }
  ok() {
    return this.assertValidity();
  }
  toHex(isCompressed = true) {
    const { x, y } = this.aff();
    const head = isCompressed ? (y & 1n) === 0n ? "02" : "03" : "04";
    return head + n2h(x) + (isCompressed ? "" : n2h(y));
  }
  toRawBytes(isCompressed = true) {
    return h2b(this.toHex(isCompressed));
  }
}
Point.BASE = new Point(Gx, Gy, 1n);
Point.ZERO = new Point(0n, 1n, 0n);
var { BASE: G, ZERO: I } = Point;
var padh = (n, pad) => n.toString(16).padStart(pad, "0");
var b2h = (b) => Array.from(b).map((e) => padh(e, 2)).join("");
var h2b = (hex) => {
  const l = hex.length;
  if (!str(hex) || l % 2)
    err("hex invalid 1");
  const arr = u8n(l / 2);
  for (let i = 0;i < arr.length; i++) {
    const j = i * 2;
    const h = hex.slice(j, j + 2);
    const b = Number.parseInt(h, 16);
    if (Number.isNaN(b) || b < 0)
      err("hex invalid 2");
    arr[i] = b;
  }
  return arr;
};
var b2n = (b) => BigInt("0x" + (b2h(b) || "0"));
var slcNum = (b, from, to) => b2n(b.slice(from, to));
var n2b = (num) => {
  return big(num) && num >= 0n && num < B256 ? h2b(padh(num, 2 * fLen)) : err("bigint expected");
};
var n2h = (num) => b2h(n2b(num));
var concatB = (...arrs) => {
  const r = u8n(arrs.reduce((sum, a) => sum + au8(a).length, 0));
  let pad = 0;
  arrs.forEach((a) => {
    r.set(a, pad);
    pad += a.length;
  });
  return r;
};
var inv = (num, md = P) => {
  if (num === 0n || md <= 0n)
    err("no inverse n=" + num + " mod=" + md);
  let a = mod(num, md), b = md, x = 0n, y = 1n, u = 1n, v = 0n;
  while (a !== 0n) {
    const q = b / a, r = b % a;
    const m = x - u * q, n = y - v * q;
    b = a, a = r, x = u, y = v, u = m, v = n;
  }
  return b === 1n ? mod(x, md) : err("no inverse");
};
var sqrt = (n) => {
  let r = 1n;
  for (let num = n, e = (P + 1n) / 4n;e > 0n; e >>= 1n) {
    if (e & 1n)
      r = r * num % P;
    num = num * num % P;
  }
  return mod(r * r) === n ? r : err("sqrt invalid");
};
var toPriv = (p) => {
  if (!big(p))
    p = b2n(toU8(p, fLen));
  return ge(p) ? p : err("private key out of range");
};
var moreThanHalfN = (n) => n > N >> 1n;
class Signature {
  constructor(r, s, recovery) {
    this.r = r;
    this.s = s;
    this.recovery = recovery;
    this.assertValidity();
  }
  static fromCompact(hex) {
    hex = toU8(hex, 64);
    return new Signature(slcNum(hex, 0, fLen), slcNum(hex, fLen, 2 * fLen));
  }
  assertValidity() {
    return ge(this.r) && ge(this.s) ? this : err();
  }
  addRecoveryBit(rec) {
    return new Signature(this.r, this.s, rec);
  }
  hasHighS() {
    return moreThanHalfN(this.s);
  }
  normalizeS() {
    return this.hasHighS() ? new Signature(this.r, mod(this.s, N), this.recovery) : this;
  }
  recoverPublicKey(msgh) {
    const { r, s, recovery: rec } = this;
    if (![0, 1, 2, 3].includes(rec))
      err("recovery id invalid");
    const h = bits2int_modN(toU8(msgh, fLen));
    const radj = rec === 2 || rec === 3 ? r + N : r;
    if (radj >= P)
      err("q.x invalid");
    const head = (rec & 1) === 0 ? "02" : "03";
    const R = Point.fromHex(head + n2h(radj));
    const ir = inv(radj, N);
    const u1 = mod(-h * ir, N);
    const u2 = mod(s * ir, N);
    return G.mulAddQUns(R, u1, u2);
  }
  toCompactRawBytes() {
    return h2b(this.toCompactHex());
  }
  toCompactHex() {
    return n2h(this.r) + n2h(this.s);
  }
}
var bits2int = (bytes) => {
  const delta = bytes.length * 8 - 256;
  const num = b2n(bytes);
  return delta > 0 ? num >> BigInt(delta) : num;
};
var bits2int_modN = (bytes) => {
  return mod(bits2int(bytes), N);
};
var i2o = (num) => n2b(num);
var cr = () => typeof globalThis === "object" && ("crypto" in globalThis) ? globalThis.crypto : undefined;
var _hmacSync;
var optS = { lowS: true };
var prepSig = (msgh, priv, opts = optS) => {
  if (["der", "recovered", "canonical"].some((k) => (k in opts)))
    err("sign() legacy options not supported");
  let { lowS } = opts;
  if (lowS == null)
    lowS = true;
  const h1i = bits2int_modN(toU8(msgh));
  const h1o = i2o(h1i);
  const d = toPriv(priv);
  const seed = [i2o(d), h1o];
  let ent = opts.extraEntropy;
  if (ent) {
    if (ent === true)
      ent = etc.randomBytes(fLen);
    const e = toU8(ent);
    if (e.length !== fLen)
      err();
    seed.push(e);
  }
  const m = h1i;
  const k2sig = (kBytes) => {
    const k = bits2int(kBytes);
    if (!ge(k))
      return;
    const ik = inv(k, N);
    const q = G.mul(k).aff();
    const r = mod(q.x, N);
    if (r === 0n)
      return;
    const s = mod(ik * mod(m + mod(d * r, N), N), N);
    if (s === 0n)
      return;
    let normS = s;
    let rec = (q.x === r ? 0 : 2) | Number(q.y & 1n);
    if (lowS && moreThanHalfN(s)) {
      normS = mod(-s, N);
      rec ^= 1;
    }
    return new Signature(r, normS, rec);
  };
  return { seed: concatB(...seed), k2sig };
};
var sign = (msgh, priv, opts = optS) => {
  const { seed, k2sig } = prepSig(msgh, priv, opts);
  return hmacDrbg(false)(seed, k2sig);
};
var hashToPrivateKey = (hash) => {
  hash = toU8(hash);
  const minLen = fLen + 8;
  if (hash.length < minLen || hash.length > 1024)
    err("expected proper params");
  const num = mod(b2n(hash), N - 1n) + 1n;
  return n2b(num);
};
var etc = {
  hexToBytes: h2b,
  bytesToHex: b2h,
  concatBytes: concatB,
  bytesToNumberBE: b2n,
  numberToBytesBE: n2b,
  mod,
  invert: inv,
  hmacSha256Async: async (key, ...msgs) => {
    const c = cr();
    const s = c && c.subtle;
    if (!s)
      return err("etc.hmacSha256Async not set");
    const k = await s.importKey("raw", key, { name: "HMAC", hash: { name: "SHA-256" } }, false, ["sign"]);
    return u8n(await s.sign("HMAC", k, concatB(...msgs)));
  },
  hmacSha256Sync: _hmacSync,
  hashToPrivateKey,
  randomBytes: (len = 32) => {
    const crypto = cr();
    if (!crypto || !crypto.getRandomValues)
      err("crypto.getRandomValues must be defined");
    return crypto.getRandomValues(u8n(len));
  }
};
Object.defineProperties(etc, { hmacSha256Sync: {
  configurable: false,
  get() {
    return _hmacSync;
  },
  set(f) {
    if (!_hmacSync)
      _hmacSync = f;
  }
} });
var W = 8;
var precompute = () => {
  const points = [];
  const windows = 256 / W + 1;
  let p = G, b = p;
  for (let w = 0;w < windows; w++) {
    b = p;
    points.push(b);
    for (let i = 1;i < 2 ** (W - 1); i++) {
      b = b.add(p);
      points.push(b);
    }
    p = b.double();
  }
  return points;
};
var Gpows = undefined;
var wNAF = (n) => {
  const comp = Gpows || (Gpows = precompute());
  const neg = (cnd, p2) => {
    let n2 = p2.negate();
    return cnd ? n2 : p2;
  };
  let p = I, f = G;
  const windows = 1 + 256 / W;
  const wsize = 2 ** (W - 1);
  const mask = BigInt(2 ** W - 1);
  const maxNum = 2 ** W;
  const shiftBy = BigInt(W);
  for (let w = 0;w < windows; w++) {
    const off = w * wsize;
    let wbits = Number(n & mask);
    n >>= shiftBy;
    if (wbits > wsize) {
      wbits -= maxNum;
      n += 1n;
    }
    const off1 = off, off2 = off + Math.abs(wbits) - 1;
    const cnd1 = w % 2 !== 0, cnd2 = wbits < 0;
    if (wbits === 0) {
      f = f.add(neg(cnd1, comp[off1]));
    } else {
      p = p.add(neg(cnd2, comp[off2]));
    }
  }
  return { p, f };
};

function number(n) {
  if (!Number.isSafeInteger(n) || n < 0)
    throw new Error(`positive integer expected, not ${n}`);
}
function isBytes(a) {
  return a instanceof Uint8Array || a != null && typeof a === "object" && a.constructor.name === "Uint8Array";
}
function bytes(b, ...lengths) {
  if (!isBytes(b))
    throw new Error("Uint8Array expected");
  if (lengths.length > 0 && !lengths.includes(b.length))
    throw new Error(`Uint8Array expected of length ${lengths}, not of length=${b.length}`);
}
function hash(h) {
  if (typeof h !== "function" || typeof h.create !== "function")
    throw new Error("Hash should be wrapped by utils.wrapConstructor");
  number(h.outputLen);
  number(h.blockLen);
}
function exists(instance, checkFinished = true) {
  if (instance.destroyed)
    throw new Error("Hash instance has been destroyed");
  if (checkFinished && instance.finished)
    throw new Error("Hash#digest() has already been called");
}
function output(out, instance) {
  bytes(out);
  const min = instance.outputLen;
  if (out.length < min) {
    throw new Error(`digestInto() expects output buffer of length at least ${min}`);
  }
}

function fromBig(n, le = false) {
  if (le)
    return { h: Number(n & U32_MASK64), l: Number(n >> _32n & U32_MASK64) };
  return { h: Number(n >> _32n & U32_MASK64) | 0, l: Number(n & U32_MASK64) | 0 };
}
function split(lst, le = false) {
  let Ah = new Uint32Array(lst.length);
  let Al = new Uint32Array(lst.length);
  for (let i = 0;i < lst.length; i++) {
    const { h, l } = fromBig(lst[i], le);
    [Ah[i], Al[i]] = [h, l];
  }
  return [Ah, Al];
}
var U32_MASK64 = /* @__PURE__ */ BigInt(2 ** 32 - 1);
var _32n = /* @__PURE__ */ BigInt(32);
var rotlSH = (h, l, s) => h << s | l >>> 32 - s;
var rotlSL = (h, l, s) => l << s | h >>> 32 - s;
var rotlBH = (h, l, s) => l << s - 32 | h >>> 64 - s;
var rotlBL = (h, l, s) => h << s - 32 | l >>> 64 - s;

function byteSwap32(arr) {
  for (let i = 0;i < arr.length; i++) {
    arr[i] = byteSwap(arr[i]);
  }
}
function utf8ToBytes(str2) {
  if (typeof str2 !== "string")
    throw new Error(`utf8ToBytes expected string, got ${typeof str2}`);
  return new Uint8Array(new TextEncoder().encode(str2));
}
function toBytes(data) {
  if (typeof data === "string")
    data = utf8ToBytes(data);
  bytes(data);
  return data;
}
function wrapConstructor(hashCons) {
  const hashC = (msg) => hashCons().update(toBytes(msg)).digest();
  const tmp = hashCons();
  hashC.outputLen = tmp.outputLen;
  hashC.blockLen = tmp.blockLen;
  hashC.create = () => hashCons();
  return hashC;
}
function wrapXOFConstructorWithOpts(hashCons) {
  const hashC = (msg, opts) => hashCons(opts).update(toBytes(msg)).digest();
  const tmp = hashCons({});
  hashC.outputLen = tmp.outputLen;
  hashC.blockLen = tmp.blockLen;
  hashC.create = (opts) => hashCons(opts);
  return hashC;
}
/*! noble-hashes - MIT License (c) 2022 Paul Miller (paulmillr.com) */
var u32 = (arr) => new Uint32Array(arr.buffer, arr.byteOffset, Math.floor(arr.byteLength / 4));
var createView = (arr) => new DataView(arr.buffer, arr.byteOffset, arr.byteLength);
var rotr = (word, shift) => word << 32 - shift | word >>> shift;
var isLE = new Uint8Array(new Uint32Array([287454020]).buffer)[0] === 68;
var byteSwap = (word) => word << 24 & 4278190080 | word << 8 & 16711680 | word >>> 8 & 65280 | word >>> 24 & 255;
class Hash {
  clone() {
    return this._cloneInto();
  }
}
var toStr = {}.toString;

function keccakP(s, rounds = 24) {
  const B = new Uint32Array(5 * 2);
  for (let round = 24 - rounds;round < 24; round++) {
    for (let x = 0;x < 10; x++)
      B[x] = s[x] ^ s[x + 10] ^ s[x + 20] ^ s[x + 30] ^ s[x + 40];
    for (let x = 0;x < 10; x += 2) {
      const idx1 = (x + 8) % 10;
      const idx0 = (x + 2) % 10;
      const B0 = B[idx0];
      const B1 = B[idx0 + 1];
      const Th = rotlH(B0, B1, 1) ^ B[idx1];
      const Tl = rotlL(B0, B1, 1) ^ B[idx1 + 1];
      for (let y = 0;y < 50; y += 10) {
        s[x + y] ^= Th;
        s[x + y + 1] ^= Tl;
      }
    }
    let curH = s[2];
    let curL = s[3];
    for (let t = 0;t < 24; t++) {
      const shift = SHA3_ROTL[t];
      const Th = rotlH(curH, curL, shift);
      const Tl = rotlL(curH, curL, shift);
      const PI = SHA3_PI[t];
      curH = s[PI];
      curL = s[PI + 1];
      s[PI] = Th;
      s[PI + 1] = Tl;
    }
    for (let y = 0;y < 50; y += 10) {
      for (let x = 0;x < 10; x++)
        B[x] = s[y + x];
      for (let x = 0;x < 10; x++)
        s[y + x] ^= ~B[(x + 2) % 10] & B[(x + 4) % 10];
    }
    s[0] ^= SHA3_IOTA_H[round];
    s[1] ^= SHA3_IOTA_L[round];
  }
  B.fill(0);
}
var SHA3_PI = [];
var SHA3_ROTL = [];
var _SHA3_IOTA = [];
var _0n = /* @__PURE__ */ BigInt(0);
var _1n = /* @__PURE__ */ BigInt(1);
var _2n = /* @__PURE__ */ BigInt(2);
var _7n = /* @__PURE__ */ BigInt(7);
var _256n = /* @__PURE__ */ BigInt(256);
var _0x71n = /* @__PURE__ */ BigInt(113);
for (let round = 0, R = _1n, x = 1, y = 0;round < 24; round++) {
  [x, y] = [y, (2 * x + 3 * y) % 5];
  SHA3_PI.push(2 * (5 * y + x));
  SHA3_ROTL.push((round + 1) * (round + 2) / 2 % 64);
  let t = _0n;
  for (let j = 0;j < 7; j++) {
    R = (R << _1n ^ (R >> _7n) * _0x71n) % _256n;
    if (R & _2n)
      t ^= _1n << (_1n << /* @__PURE__ */ BigInt(j)) - _1n;
  }
  _SHA3_IOTA.push(t);
}
var [SHA3_IOTA_H, SHA3_IOTA_L] = /* @__PURE__ */ split(_SHA3_IOTA, true);
var rotlH = (h, l, s) => s > 32 ? rotlBH(h, l, s) : rotlSH(h, l, s);
var rotlL = (h, l, s) => s > 32 ? rotlBL(h, l, s) : rotlSL(h, l, s);

class Keccak extends Hash {
  constructor(blockLen, suffix, outputLen, enableXOF = false, rounds = 24) {
    super();
    this.blockLen = blockLen;
    this.suffix = suffix;
    this.outputLen = outputLen;
    this.enableXOF = enableXOF;
    this.rounds = rounds;
    this.pos = 0;
    this.posOut = 0;
    this.finished = false;
    this.destroyed = false;
    number(outputLen);
    if (0 >= this.blockLen || this.blockLen >= 200)
      throw new Error("Sha3 supports only keccak-f1600 function");
    this.state = new Uint8Array(200);
    this.state32 = u32(this.state);
  }
  keccak() {
    if (!isLE)
      byteSwap32(this.state32);
    keccakP(this.state32, this.rounds);
    if (!isLE)
      byteSwap32(this.state32);
    this.posOut = 0;
    this.pos = 0;
  }
  update(data) {
    exists(this);
    const { blockLen, state } = this;
    data = toBytes(data);
    const len = data.length;
    for (let pos = 0;pos < len; ) {
      const take = Math.min(blockLen - this.pos, len - pos);
      for (let i = 0;i < take; i++)
        state[this.pos++] ^= data[pos++];
      if (this.pos === blockLen)
        this.keccak();
    }
    return this;
  }
  finish() {
    if (this.finished)
      return;
    this.finished = true;
    const { state, suffix, pos, blockLen } = this;
    state[pos] ^= suffix;
    if ((suffix & 128) !== 0 && pos === blockLen - 1)
      this.keccak();
    state[blockLen - 1] ^= 128;
    this.keccak();
  }
  writeInto(out) {
    exists(this, false);
    bytes(out);
    this.finish();
    const bufferOut = this.state;
    const { blockLen } = this;
    for (let pos = 0, len = out.length;pos < len; ) {
      if (this.posOut >= blockLen)
        this.keccak();
      const take = Math.min(blockLen - this.posOut, len - pos);
      out.set(bufferOut.subarray(this.posOut, this.posOut + take), pos);
      this.posOut += take;
      pos += take;
    }
    return out;
  }
  xofInto(out) {
    if (!this.enableXOF)
      throw new Error("XOF is not possible for this instance");
    return this.writeInto(out);
  }
  xof(bytes2) {
    number(bytes2);
    return this.xofInto(new Uint8Array(bytes2));
  }
  digestInto(out) {
    output(out, this);
    if (this.finished)
      throw new Error("digest() was already called");
    this.writeInto(out);
    this.destroy();
    return out;
  }
  digest() {
    return this.digestInto(new Uint8Array(this.outputLen));
  }
  destroy() {
    this.destroyed = true;
    this.state.fill(0);
  }
  _cloneInto(to) {
    const { blockLen, suffix, outputLen, rounds, enableXOF } = this;
    to || (to = new Keccak(blockLen, suffix, outputLen, enableXOF, rounds));
    to.state32.set(this.state32);
    to.pos = this.pos;
    to.posOut = this.posOut;
    to.finished = this.finished;
    to.rounds = rounds;
    to.suffix = suffix;
    to.outputLen = outputLen;
    to.enableXOF = enableXOF;
    to.destroyed = this.destroyed;
    return to;
  }
}
var gen = (suffix, blockLen, outputLen) => wrapConstructor(() => new Keccak(blockLen, suffix, outputLen));
var sha3_224 = /* @__PURE__ */ gen(6, 144, 224 / 8);
var sha3_256 = /* @__PURE__ */ gen(6, 136, 256 / 8);
var sha3_384 = /* @__PURE__ */ gen(6, 104, 384 / 8);
var sha3_512 = /* @__PURE__ */ gen(6, 72, 512 / 8);
var keccak_224 = /* @__PURE__ */ gen(1, 144, 224 / 8);
var keccak_256 = /* @__PURE__ */ gen(1, 136, 256 / 8);
var keccak_384 = /* @__PURE__ */ gen(1, 104, 384 / 8);
var keccak_512 = /* @__PURE__ */ gen(1, 72, 512 / 8);
var genShake = (suffix, blockLen, outputLen) => wrapXOFConstructorWithOpts((opts = {}) => new Keccak(blockLen, suffix, opts.dkLen === undefined ? outputLen : opts.dkLen, true));
var shake128 = /* @__PURE__ */ genShake(31, 168, 128 / 8);
var shake256 = /* @__PURE__ */ genShake(31, 136, 256 / 8);

class HMAC extends Hash {
  constructor(hash2, _key) {
    super();
    this.finished = false;
    this.destroyed = false;
    hash(hash2);
    const key = toBytes(_key);
    this.iHash = hash2.create();
    if (typeof this.iHash.update !== "function")
      throw new Error("Expected instance of class which extends utils.Hash");
    this.blockLen = this.iHash.blockLen;
    this.outputLen = this.iHash.outputLen;
    const blockLen = this.blockLen;
    const pad = new Uint8Array(blockLen);
    pad.set(key.length > blockLen ? hash2.create().update(key).digest() : key);
    for (let i = 0;i < pad.length; i++)
      pad[i] ^= 54;
    this.iHash.update(pad);
    this.oHash = hash2.create();
    for (let i = 0;i < pad.length; i++)
      pad[i] ^= 54 ^ 92;
    this.oHash.update(pad);
    pad.fill(0);
  }
  update(buf) {
    exists(this);
    this.iHash.update(buf);
    return this;
  }
  digestInto(out) {
    exists(this);
    bytes(out, this.outputLen);
    this.finished = true;
    this.iHash.digestInto(out);
    this.oHash.update(out);
    this.oHash.digestInto(out);
    this.destroy();
  }
  digest() {
    const out = new Uint8Array(this.oHash.outputLen);
    this.digestInto(out);
    return out;
  }
  _cloneInto(to) {
    to || (to = Object.create(Object.getPrototypeOf(this), {}));
    const { oHash, iHash, finished, destroyed, blockLen, outputLen } = this;
    to = to;
    to.finished = finished;
    to.destroyed = destroyed;
    to.blockLen = blockLen;
    to.outputLen = outputLen;
    to.oHash = oHash._cloneInto(to.oHash);
    to.iHash = iHash._cloneInto(to.iHash);
    return to;
  }
  destroy() {
    this.destroyed = true;
    this.oHash.destroy();
    this.iHash.destroy();
  }
}
var hmac = (hash2, key, message) => new HMAC(hash2, key).update(message).digest();
hmac.create = (hash2, key) => new HMAC(hash2, key);

function setBigUint64(view, byteOffset, value, isLE2) {
  if (typeof view.setBigUint64 === "function")
    return view.setBigUint64(byteOffset, value, isLE2);
  const _32n2 = BigInt(32);
  const _u32_max = BigInt(4294967295);
  const wh = Number(value >> _32n2 & _u32_max);
  const wl = Number(value & _u32_max);
  const h = isLE2 ? 4 : 0;
  const l = isLE2 ? 0 : 4;
  view.setUint32(byteOffset + h, wh, isLE2);
  view.setUint32(byteOffset + l, wl, isLE2);
}
var Chi = (a, b, c) => a & b ^ ~a & c;
var Maj = (a, b, c) => a & b ^ a & c ^ b & c;

class HashMD extends Hash {
  constructor(blockLen, outputLen, padOffset, isLE2) {
    super();
    this.blockLen = blockLen;
    this.outputLen = outputLen;
    this.padOffset = padOffset;
    this.isLE = isLE2;
    this.finished = false;
    this.length = 0;
    this.pos = 0;
    this.destroyed = false;
    this.buffer = new Uint8Array(blockLen);
    this.view = createView(this.buffer);
  }
  update(data) {
    exists(this);
    const { view, buffer, blockLen } = this;
    data = toBytes(data);
    const len = data.length;
    for (let pos = 0;pos < len; ) {
      const take = Math.min(blockLen - this.pos, len - pos);
      if (take === blockLen) {
        const dataView = createView(data);
        for (;blockLen <= len - pos; pos += blockLen)
          this.process(dataView, pos);
        continue;
      }
      buffer.set(data.subarray(pos, pos + take), this.pos);
      this.pos += take;
      pos += take;
      if (this.pos === blockLen) {
        this.process(view, 0);
        this.pos = 0;
      }
    }
    this.length += data.length;
    this.roundClean();
    return this;
  }
  digestInto(out) {
    exists(this);
    output(out, this);
    this.finished = true;
    const { buffer, view, blockLen, isLE: isLE2 } = this;
    let { pos } = this;
    buffer[pos++] = 128;
    this.buffer.subarray(pos).fill(0);
    if (this.padOffset > blockLen - pos) {
      this.process(view, 0);
      pos = 0;
    }
    for (let i = pos;i < blockLen; i++)
      buffer[i] = 0;
    setBigUint64(view, blockLen - 8, BigInt(this.length * 8), isLE2);
    this.process(view, 0);
    const oview = createView(out);
    const len = this.outputLen;
    if (len % 4)
      throw new Error("_sha2: outputLen should be aligned to 32bit");
    const outLen = len / 4;
    const state = this.get();
    if (outLen > state.length)
      throw new Error("_sha2: outputLen bigger than state");
    for (let i = 0;i < outLen; i++)
      oview.setUint32(4 * i, state[i], isLE2);
  }
  digest() {
    const { buffer, outputLen } = this;
    this.digestInto(buffer);
    const res = buffer.slice(0, outputLen);
    this.destroy();
    return res;
  }
  _cloneInto(to) {
    to || (to = new this.constructor);
    to.set(...this.get());
    const { blockLen, buffer, length, finished, destroyed, pos } = this;
    to.length = length;
    to.pos = pos;
    to.finished = finished;
    to.destroyed = destroyed;
    if (length % blockLen)
      to.buffer.set(buffer);
    return to;
  }
}

var SHA256_K = /* @__PURE__ */ new Uint32Array([
  1116352408,
  1899447441,
  3049323471,
  3921009573,
  961987163,
  1508970993,
  2453635748,
  2870763221,
  3624381080,
  310598401,
  607225278,
  1426881987,
  1925078388,
  2162078206,
  2614888103,
  3248222580,
  3835390401,
  4022224774,
  264347078,
  604807628,
  770255983,
  1249150122,
  1555081692,
  1996064986,
  2554220882,
  2821834349,
  2952996808,
  3210313671,
  3336571891,
  3584528711,
  113926993,
  338241895,
  666307205,
  773529912,
  1294757372,
  1396182291,
  1695183700,
  1986661051,
  2177026350,
  2456956037,
  2730485921,
  2820302411,
  3259730800,
  3345764771,
  3516065817,
  3600352804,
  4094571909,
  275423344,
  430227734,
  506948616,
  659060556,
  883997877,
  958139571,
  1322822218,
  1537002063,
  1747873779,
  1955562222,
  2024104815,
  2227730452,
  2361852424,
  2428436474,
  2756734187,
  3204031479,
  3329325298
]);
var SHA256_IV = /* @__PURE__ */ new Uint32Array([
  1779033703,
  3144134277,
  1013904242,
  2773480762,
  1359893119,
  2600822924,
  528734635,
  1541459225
]);
var SHA256_W = /* @__PURE__ */ new Uint32Array(64);

class SHA256 extends HashMD {
  constructor() {
    super(64, 32, 8, false);
    this.A = SHA256_IV[0] | 0;
    this.B = SHA256_IV[1] | 0;
    this.C = SHA256_IV[2] | 0;
    this.D = SHA256_IV[3] | 0;
    this.E = SHA256_IV[4] | 0;
    this.F = SHA256_IV[5] | 0;
    this.G = SHA256_IV[6] | 0;
    this.H = SHA256_IV[7] | 0;
  }
  get() {
    const { A, B, C, D, E, F, G: G2, H } = this;
    return [A, B, C, D, E, F, G2, H];
  }
  set(A, B, C, D, E, F, G2, H) {
    this.A = A | 0;
    this.B = B | 0;
    this.C = C | 0;
    this.D = D | 0;
    this.E = E | 0;
    this.F = F | 0;
    this.G = G2 | 0;
    this.H = H | 0;
  }
  process(view, offset) {
    for (let i = 0;i < 16; i++, offset += 4)
      SHA256_W[i] = view.getUint32(offset, false);
    for (let i = 16;i < 64; i++) {
      const W15 = SHA256_W[i - 15];
      const W2 = SHA256_W[i - 2];
      const s0 = rotr(W15, 7) ^ rotr(W15, 18) ^ W15 >>> 3;
      const s1 = rotr(W2, 17) ^ rotr(W2, 19) ^ W2 >>> 10;
      SHA256_W[i] = s1 + SHA256_W[i - 7] + s0 + SHA256_W[i - 16] | 0;
    }
    let { A, B, C, D, E, F, G: G2, H } = this;
    for (let i = 0;i < 64; i++) {
      const sigma1 = rotr(E, 6) ^ rotr(E, 11) ^ rotr(E, 25);
      const T1 = H + sigma1 + Chi(E, F, G2) + SHA256_K[i] + SHA256_W[i] | 0;
      const sigma0 = rotr(A, 2) ^ rotr(A, 13) ^ rotr(A, 22);
      const T2 = sigma0 + Maj(A, B, C) | 0;
      H = G2;
      G2 = F;
      F = E;
      E = D + T1 | 0;
      D = C;
      C = B;
      B = A;
      A = T1 + T2 | 0;
    }
    A = A + this.A | 0;
    B = B + this.B | 0;
    C = C + this.C | 0;
    D = D + this.D | 0;
    E = E + this.E | 0;
    F = F + this.F | 0;
    G2 = G2 + this.G | 0;
    H = H + this.H | 0;
    this.set(A, B, C, D, E, F, G2, H);
  }
  roundClean() {
    SHA256_W.fill(0);
  }
  destroy() {
    this.set(0, 0, 0, 0, 0, 0, 0, 0);
    this.buffer.fill(0);
  }
}
var sha256 = /* @__PURE__ */ wrapConstructor(() => new SHA256);

var nobleP256 = function() {
  etc.hmacSha256Sync = (k, ...m) => hmac(sha256, k, etc.concatBytes(...m));
  const MessagePrefix = `\x19Ethereum Signed Message:
`;
  const hexes = Array.from({ length: 256 }, (v, i) => i.toString(16).padStart(2, "0"));
  function bytesToHex(uint8a) {
    if (!(uint8a instanceof Uint8Array)) {
      throw new Error("Uint8Array expected");
    }
    let hex = "";
    for (let i = 0;i < uint8a.length; i++) {
      hex += hexes[uint8a[i]];
    }
    return hex;
  }
  function hexToBytes(hex) {
    if (typeof hex !== "string") {
      console.log(hex);
      throw new TypeError("hexToBytes: expected string, got " + typeof hex);
    }
    if (hex.length % 2) {
      throw new Error("hexToBytes: received invalid unpadded hex");
    }
    const array = new Uint8Array(hex.length / 2);
    for (let i = 0;i < array.length; i++) {
      const j = i * 2;
      const hexByte = hex.slice(j, j + 2);
      const byte = Number.parseInt(hexByte, 16);
      if (Number.isNaN(byte) || byte < 0) {
        throw new Error("Invalid byte sequence");
      }
      array[i] = byte;
    }
    return array;
  }
  function utf8ToUint8Array(str2) {
    let i = 0, bytes2 = new Uint8Array(str2.length * 4);
    for (let ci = 0;ci !== str2.length; ci++) {
      let c = str2.charCodeAt(ci);
      if (c < 128) {
        bytes2[i++] = c;
        continue;
      }
      if (c < 2048) {
        bytes2[i++] = c >> 6 | 192;
      } else {
        if (c > 55295 && c < 56320) {
          if (++ci >= str2.length)
            throw new Error("UTF-8 encode: incomplete surrogate pair");
          let c2 = str2.charCodeAt(ci);
          if (c2 < 56320 || c2 > 57343)
            throw new Error("UTF-8 encode: second surrogate character 0x" + c2.toString(16) + " at index " + ci + " out of range");
          c = 65536 + ((c & 1023) << 10) + (c2 & 1023);
          bytes2[i++] = c >> 18 | 240;
          bytes2[i++] = c >> 12 & 63 | 128;
        } else
          bytes2[i++] = c >> 12 | 224;
        bytes2[i++] = c >> 6 & 63 | 128;
      }
      bytes2[i++] = c & 63 | 128;
    }
    return bytes2.subarray(0, i);
  }
  function hashMessage(messageUint8Array) {
    const lengthHex = bytesToHex(utf8ToUint8Array(String(messageUint8Array.length)));
    const prefixHex = bytesToHex(utf8ToUint8Array(MessagePrefix));
    const messageHex = `${prefixHex}${lengthHex}${bytesToHex(messageUint8Array)}`;
    return keccak_256(hexToBytes(messageHex));
  }
  return {
    sign: (messageHash, privateKeyHex) => {
      const ownHash = hashMessage(messageHash);
      return sign(ownHash, hexToBytes(privateKeyHex)).toCompactHex();
    }
  };
}();
