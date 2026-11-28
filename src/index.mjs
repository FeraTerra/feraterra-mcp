import { createHmac, randomBytes } from "node:crypto";

export const PACKAGE_VERSION = "4.9.5";
export const SDK_VERSION = "4.9.5";
export const DEFAULT_FERATERRA_API_URL = "https://testnet.feraterra.app";
export const MAINNET_FERATERRA_API_URL = "https://api.feraterra.app";
export const REMOTE_FERATERRA_MCP_URL = "https://mcp.feraterra.app/mcp";
export const PRICE_TICKS_PER_USD = 100;
export const LOTS_PER_BASE_UNIT = 10_000;
export const MICRO_USD_PER_DOLLAR = 1_000_000;
export const MAX_RESPONSE_BYTES = 4 * 1024 * 1024;

const MASK64 = 0xffff_ffff_ffff_ffffn;
const SECP_P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;
const SECP_N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const SECP_GX = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n;
const SECP_GY = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n;
const SECP_HALF_N = SECP_N >> 1n;
const SECP_SQRT_EXP = (SECP_P + 1n) >> 2n;

const KECCAK_RC = [
  0x0000000000000001n, 0x0000000000008082n, 0x800000000000808an, 0x8000000080008000n,
  0x000000000000808bn, 0x0000000080000001n, 0x8000000080008081n, 0x8000000000008009n,
  0x000000000000008an, 0x0000000000000088n, 0x0000000080008009n, 0x000000008000000an,
  0x000000008000808bn, 0x800000000000008bn, 0x8000000000008089n, 0x8000000000008003n,
  0x8000000000008002n, 0x8000000000000080n, 0x000000000000800an, 0x800000008000000an,
  0x8000000080008081n, 0x8000000000008080n, 0x0000000080000001n, 0x8000000080008008n,
];

const KECCAK_RHO = [
  1n, 3n, 6n, 10n, 15n, 21n, 28n, 36n, 45n, 55n, 2n, 14n,
  27n, 41n, 56n, 8n, 25n, 43n, 62n, 18n, 39n, 61n, 20n, 44n,
];

const KECCAK_PI = [
  10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
  15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
];

const TEXT_ENCODER = new TextEncoder();
const TEXT_DECODER = new TextDecoder("utf-8");

export class FeraTerraError extends Error {
  constructor(message, options = {}) {
    super(message);
    this.name = "FeraTerraError";
    if (options.status !== undefined) this.status = options.status;
    if (options.code !== undefined) this.code = options.code;
  }
}

export function strictBool(val, defaultVal = false) {
  if (val === undefined || val === null) {
    return defaultVal;
  }
  if (typeof val === "boolean") {
    return val;
  }
  if (typeof val === "string") {
    const norm = val.trim().toLowerCase();
    if (norm === "true") return true;
    if (norm === "false") return false;
  }
  throw new FeraTerraError(
    `Invalid boolean value: ${String(val)} (expected boolean or "true"/"false")`
  );
}

export function isLoopbackHostname(hostname) {
  const h = String(hostname || "").trim().toLowerCase();
  if (h === "localhost" || h === "[::1]" || h === "::1") {
    return true;
  }
  const ipv4 = /^127\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(h);
  if (!ipv4) {
    return false;
  }
  return (
    Number(ipv4[1]) <= 255 &&
    Number(ipv4[2]) <= 255 &&
    Number(ipv4[3]) <= 255
  );
}

export function validateEndpointUrl(rawUrl, label = "baseUrl") {
  const input = String(rawUrl ?? "").trim();
  if (!input) {
    throw new FeraTerraError(`${label} must be a non-empty URL`);
  }
  if (input.includes("?") || input.includes("#")) {
    throw new FeraTerraError(`${label} must not contain query parameters or hash fragments`);
  }
  let parsed;
  try {
    parsed = new URL(input);
  } catch {
    throw new FeraTerraError(`Invalid ${label}: ${input}`);
  }
  if (parsed.username || parsed.password) {
    throw new FeraTerraError(`${label} must not contain embedded userinfo credentials`);
  }
  if (parsed.search || parsed.hash) {
    throw new FeraTerraError(`${label} must not contain query parameters or hash fragments`);
  }
  if (parsed.protocol === "https:") {
    // Allowed
  } else if (parsed.protocol === "http:") {
    if (!isLoopbackHostname(parsed.hostname)) {
      throw new FeraTerraError(
        `Insecure http: ${label} is only permitted for loopback hosts (127.0.0.1, localhost, [::1]); got ${parsed.origin}`
      );
    }
  } else {
    throw new FeraTerraError(
      `Unsupported ${label} protocol ${parsed.protocol} (expected https: or loopback http:)`
    );
  }
  const cleanPath = parsed.pathname.replace(/\/+$/, "");
  return `${parsed.origin}${cleanPath}`;
}

async function readResponseTextBounded(resp, maxBytes = MAX_RESPONSE_BYTES) {
  if (typeof resp?.headers?.get === "function") {
    const clRaw = resp.headers.get("content-length");
    if (clRaw !== null && clRaw !== undefined && String(clRaw).trim() !== "") {
      const declaredLen = Number(clRaw);
      if (Number.isFinite(declaredLen) && declaredLen > maxBytes) {
        if (resp.body && typeof resp.body.cancel === "function") {
          await resp.body.cancel().catch(() => {});
        }
        throw new FeraTerraError(
          `Response Content-Length (${declaredLen} bytes) exceeds ${maxBytes}-byte safety cap`,
          { status: resp.status, code: "response_too_large" }
        );
      }
    }
  }
  if (resp?.body && typeof resp.body.getReader === "function") {
    const reader = resp.body.getReader();
    const chunks = [];
    let totalBytes = 0;
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        const chunk = value instanceof Uint8Array ? value : new Uint8Array(value);
        totalBytes += chunk.byteLength;
        if (totalBytes > maxBytes) {
          await reader.cancel().catch(() => {});
          throw new FeraTerraError(
            `Response body exceeded ${maxBytes}-byte (4 MiB) safety cap`,
            { status: resp.status, code: "response_too_large" }
          );
        }
        chunks.push(chunk);
      }
    } finally {
      if (typeof reader.releaseLock === "function") {
        reader.releaseLock();
      }
    }
    const merged = new Uint8Array(totalBytes);
    let offset = 0;
    for (const c of chunks) {
      merged.set(c, offset);
      offset += c.byteLength;
    }
    return TEXT_DECODER.decode(merged);
  }
  const rawText = await resp.text();
  const byteLen = Buffer.byteLength(rawText, "utf8");
  if (byteLen > maxBytes) {
    throw new FeraTerraError(
      `Response body (${byteLen} bytes) exceeded ${maxBytes}-byte (4 MiB) safety cap`,
      { status: resp.status, code: "response_too_large" }
    );
  }
  return rawText;
}

function formatFixedScale(rawUnits, decimals) {
  let n;
  if (typeof rawUnits === "bigint") {
    n = rawUnits;
  } else if (typeof rawUnits === "string" && /^[+-]?\d+$/.test(rawUnits.trim())) {
    n = BigInt(rawUnits.trim());
  } else {
    const num = Number(rawUnits);
    if (!Number.isFinite(num)) {
      throw new TypeError(`Invalid integer unit value: ${String(rawUnits)}`);
    }
    n = BigInt(Math.trunc(num));
  }
  const neg = n < 0n;
  const abs = neg ? -n : n;
  const scale = 10n ** BigInt(decimals);
  const whole = abs / scale;
  const frac = (abs % scale).toString().padStart(decimals, "0");
  return `${neg ? "-" : ""}${whole.toString()}.${frac}`;
}

function parseFixedScale(value, decimals, scaleInt, fieldName) {
  if (typeof value === "bigint") {
    const scaled = value * BigInt(scaleInt);
    const asNum = Number(scaled);
    if (!Number.isSafeInteger(asNum)) {
      throw new RangeError(`Scaled ${fieldName} exceeds safe integer range: ${String(value)}`);
    }
    return asNum;
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new TypeError(`Invalid numeric ${fieldName}: ${String(value)}`);
    }
    return Math.round(value * scaleInt);
  }
  const str = String(value ?? "").trim();
  if (!str) {
    throw new TypeError(`Invalid numeric ${fieldName}: empty value`);
  }
  const decMatch = /^([+-]?)(\d+)(?:\.(\d+))?$/.exec(str);
  if (decMatch) {
    const neg = decMatch[1] === "-";
    const whole = BigInt(decMatch[2]);
    const fracRaw = decMatch[3] || "";
    const padded = fracRaw.padEnd(decimals + 1, "0");
    const mainFrac = decimals > 0 ? BigInt(padded.slice(0, decimals)) : 0n;
    const roundDigit = Number(padded[decimals] || "0");
    let total = whole * BigInt(scaleInt) + mainFrac;
    if (roundDigit >= 5) {
      total += 1n;
    }
    const signed = neg ? -total : total;
    const asNum = Number(signed);
    if (!Number.isSafeInteger(asNum)) {
      throw new RangeError(`Scaled ${fieldName} exceeds safe integer range: ${str}`);
    }
    return asNum;
  }
  const fallback = Number(str);
  if (!Number.isFinite(fallback)) {
    throw new TypeError(`Invalid numeric ${fieldName}: ${String(value)}`);
  }
  return Math.round(fallback * scaleInt);
}

export function ticksToUsd(ticks) {
  return formatFixedScale(ticks, 2);
}

export function usdToTicks(usd) {
  return parseFixedScale(usd, 2, PRICE_TICKS_PER_USD, "usd");
}

export function lotsToBase(lots) {
  return formatFixedScale(lots, 4);
}

export function baseToLots(base) {
  return parseFixedScale(base, 4, LOTS_PER_BASE_UNIT, "base");
}

export function microToUsd(micro) {
  return formatFixedScale(micro, 6);
}

export function usdToMicro(usd) {
  return parseFixedScale(usd, 6, MICRO_USD_PER_DOLLAR, "usd");
}

function rotl64(x, s) {
  return ((x << s) | (x >> (64n - s))) & MASK64;
}

function readU64LE(buf, offset) {
  let out = 0n;
  for (let i = 0; i < 8; i += 1) {
    out |= BigInt(buf[offset + i]) << BigInt(i * 8);
  }
  return out;
}

function writeU64LE(word, out, offset) {
  for (let i = 0; i < 8; i += 1) {
    out[offset + i] = Number((word >> BigInt(i * 8)) & 0xffn);
  }
}

function writeU64BE(word, out, offset) {
  const w = BigInt(word) & MASK64;
  for (let i = 0; i < 8; i += 1) {
    out[offset + 7 - i] = Number((w >> BigInt(i * 8)) & 0xffn);
  }
}

function keccakF1600(st) {
  const bc = new Array(5).fill(0n);
  for (let rnd = 0; rnd < 24; rnd += 1) {
    for (let x = 0; x < 5; x += 1) {
      bc[x] = st[x] ^ st[x + 5] ^ st[x + 10] ^ st[x + 15] ^ st[x + 20];
    }
    for (let x = 0; x < 5; x += 1) {
      const t = bc[(x + 4) % 5] ^ rotl64(bc[(x + 1) % 5], 1n);
      for (let y = 0; y < 25; y += 5) {
        st[y + x] = (st[y + x] ^ t) & MASK64;
      }
    }
    let t = st[1];
    for (let i = 0; i < 24; i += 1) {
      const j = KECCAK_PI[i];
      const next = st[j];
      st[j] = rotl64(t, KECCAK_RHO[i]);
      t = next;
    }
    for (let y = 0; y < 25; y += 5) {
      const r0 = st[y];
      const r1 = st[y + 1];
      const r2 = st[y + 2];
      const r3 = st[y + 3];
      const r4 = st[y + 4];
      st[y] = (r0 ^ ((~r1 & MASK64) & r2)) & MASK64;
      st[y + 1] = (r1 ^ ((~r2 & MASK64) & r3)) & MASK64;
      st[y + 2] = (r2 ^ ((~r3 & MASK64) & r4)) & MASK64;
      st[y + 3] = (r3 ^ ((~r4 & MASK64) & r0)) & MASK64;
      st[y + 4] = (r4 ^ ((~r0 & MASK64) & r1)) & MASK64;
    }
    st[0] = (st[0] ^ KECCAK_RC[rnd]) & MASK64;
  }
}

export function keccak256(input) {
  const bytes =
    typeof input === "string"
      ? TEXT_ENCODER.encode(input)
      : input instanceof Uint8Array
        ? input
        : new Uint8Array(input);
  const rate = 136;
  const st = new Array(25).fill(0n);
  let offset = 0;
  while (offset + rate <= bytes.length) {
    for (let i = 0; i < 17; i += 1) {
      st[i] ^= readU64LE(bytes, offset + i * 8);
    }
    keccakF1600(st);
    offset += rate;
  }
  const tail = new Uint8Array(rate);
  const rem = bytes.length - offset;
  if (rem > 0) {
    tail.set(bytes.subarray(offset), 0);
  }
  tail[rem] ^= 0x01;
  tail[rate - 1] ^= 0x80;
  for (let i = 0; i < 17; i += 1) {
    st[i] ^= readU64LE(tail, i * 8);
  }
  keccakF1600(st);
  const out = new Uint8Array(32);
  for (let i = 0; i < 4; i += 1) {
    writeU64LE(st[i], out, i * 8);
  }
  return out;
}

function bytesToHex(bytes) {
  let out = "";
  for (let i = 0; i < bytes.length; i += 1) {
    out += bytes[i].toString(16).padStart(2, "0");
  }
  return out;
}

function hexToBytes(hexStr) {
  const clean = String(hexStr || "").trim().replace(/^0x/i, "");
  if (clean.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(clean)) {
    throw new FeraTerraError(`Invalid hex string: ${String(hexStr)}`);
  }
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = Number.parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function bytesToBigIntBE(bytes) {
  let out = 0n;
  for (let i = 0; i < bytes.length; i += 1) {
    out = (out << 8n) | BigInt(bytes[i]);
  }
  return out;
}

function bigIntToBytes32BE(val) {
  const out = new Uint8Array(32);
  let cur = val;
  for (let i = 31; i >= 0; i -= 1) {
    out[i] = Number(cur & 0xffn);
    cur >>= 8n;
  }
  return out;
}

function mod(a, m) {
  const r = a % m;
  return r >= 0n ? r : r + m;
}

function modInv(a, m) {
  let t = 0n;
  let newT = 1n;
  let r = m;
  let newR = mod(a, m);
  while (newR !== 0n) {
    const q = r / newR;
    [t, newT] = [newT, t - q * newT];
    [r, newR] = [newR, r - q * newR];
  }
  if (r !== 1n) {
    throw new FeraTerraError("Element is not invertible");
  }
  return t < 0n ? t + m : t;
}

function modPow(base, exp, modulus) {
  let result = 1n;
  let b = mod(base, modulus);
  let e = exp;
  while (e > 0n) {
    if (e & 1n) {
      result = (result * b) % modulus;
    }
    b = (b * b) % modulus;
    e >>= 1n;
  }
  return result;
}

function secpPointAdd(p1, p2) {
  if (p1 === null) return p2;
  if (p2 === null) return p1;
  const [x1, y1] = p1;
  const [x2, y2] = p2;
  let lam;
  if (x1 === x2) {
    if ((y1 + y2) % SECP_P === 0n) {
      return null;
    }
    lam = (3n * x1 * x1 * modInv(2n * y1, SECP_P)) % SECP_P;
  } else {
    lam = (mod(y2 - y1, SECP_P) * modInv(mod(x2 - x1, SECP_P), SECP_P)) % SECP_P;
  }
  const x3 = mod(lam * lam - x1 - x2, SECP_P);
  const y3 = mod(lam * (x1 - x3) - y1, SECP_P);
  return [x3, y3];
}

function secpScalarMul(kScalar, point) {
  let k = mod(kScalar, SECP_N);
  if (k === 0n) return null;
  let acc = null;
  let addend = point;
  while (k > 0n) {
    if (k & 1n) {
      acc = secpPointAdd(acc, addend);
    }
    addend = secpPointAdd(addend, addend);
    k >>= 1n;
  }
  return acc;
}

function formatEip55Address(addr20) {
  const low = bytesToHex(addr20);
  const hashHex = bytesToHex(keccak256(TEXT_ENCODER.encode(low)));
  let out = "0x";
  for (let i = 0; i < 40; i += 1) {
    const ch = low[i];
    const nibble = Number.parseInt(hashHex[i], 16);
    out += ch >= "a" && ch <= "f" && nibble >= 8 ? ch.toUpperCase() : ch;
  }
  return out;
}

export function deriveEthAddress(privateKeyHex) {
  const privBytes = hexToBytes(privateKeyHex);
  if (privBytes.length !== 32) {
    throw new FeraTerraError("Expected 32-byte secp256k1 private key");
  }
  const d = bytesToBigIntBE(privBytes);
  if (d < 1n || d >= SECP_N) {
    throw new FeraTerraError("Private key scalar out of secp256k1 range");
  }
  const q = secpScalarMul(d, [SECP_GX, SECP_GY]);
  if (q === null) {
    throw new FeraTerraError("Invalid public key point");
  }
  const pub64 = new Uint8Array(64);
  pub64.set(bigIntToBytes32BE(q[0]), 0);
  pub64.set(bigIntToBytes32BE(q[1]), 32);
  return formatEip55Address(keccak256(pub64).subarray(12));
}

export function signDigestSecp256k1(digestBytes, privateKeyHex) {
  if (!(digestBytes instanceof Uint8Array) || digestBytes.length !== 32) {
    throw new FeraTerraError("Expected 32-byte digestBytes");
  }
  const privBytes = hexToBytes(privateKeyHex);
  if (privBytes.length !== 32) {
    throw new FeraTerraError("Expected 32-byte secp256k1 private key");
  }
  const d = bytesToBigIntBE(privBytes);
  if (d < 1n || d >= SECP_N) {
    throw new FeraTerraError("Private key scalar out of secp256k1 range");
  }
  const z = bytesToBigIntBE(digestBytes) % SECP_N;
  const xBytes = bigIntToBytes32BE(d);
  const h1Bytes = bigIntToBytes32BE(z);

  // RFC 6979 deterministic k generation with HMAC-SHA256
  let v = Buffer.alloc(32, 0x01);
  let kHmac = Buffer.alloc(32, 0x00);
  kHmac = createHmac("sha256", kHmac)
    .update(v)
    .update(Buffer.from([0x00]))
    .update(xBytes)
    .update(h1Bytes)
    .digest();
  v = createHmac("sha256", kHmac).update(v).digest();
  kHmac = createHmac("sha256", kHmac)
    .update(v)
    .update(Buffer.from([0x01]))
    .update(xBytes)
    .update(h1Bytes)
    .digest();
  v = createHmac("sha256", kHmac).update(v).digest();

  while (true) {
    v = createHmac("sha256", kHmac).update(v).digest();
    const k = bytesToBigIntBE(v);
    if (k >= 1n && k < SECP_N) {
      const pt = secpScalarMul(k, [SECP_GX, SECP_GY]);
      if (pt !== null) {
        const r = pt[0] % SECP_N;
        const rOverflow = pt[0] >= SECP_N ? 2 : 0;
        if (r !== 0n && rOverflow === 0) {
          const kInv = modInv(k, SECP_N);
          let s = mod(kInv * (z + r * d), SECP_N);
          if (s !== 0n) {
            let recid = Number(pt[1] & 1n);
            if (s > SECP_HALF_N) {
              s = SECP_N - s;
              recid ^= 1;
            }
            const sig = new Uint8Array(65);
            sig.set(bigIntToBytes32BE(r), 0);
            sig.set(bigIntToBytes32BE(s), 32);
            sig[64] = 27 + recid;
            return `0x${bytesToHex(sig)}`;
          }
        }
      }
    }
    kHmac = createHmac("sha256", kHmac).update(v).update(Buffer.from([0x00])).digest();
    v = createHmac("sha256", kHmac).update(v).digest();
  }
}

export function computeLedgerTipDigest({
  walSeq,
  ledgerChainHash,
  stateRoot,
  chainId = 0,
  clearinghouseAddress = "",
}) {
  const chBytes = hexToBytes(ledgerChainHash);
  const srBytes = hexToBytes(stateRoot);
  if (chBytes.length !== 32 || srBytes.length !== 32) {
    throw new FeraTerraError("ledgerChainHash and stateRoot must each be 32 bytes");
  }
  const clhRaw = String(clearinghouseAddress || "").trim();
  let clhBytes;
  if (clhRaw) {
    clhBytes = hexToBytes(clhRaw);
    if (clhBytes.length !== 20) {
      throw new FeraTerraError("clearinghouseAddress must be 20 bytes when specified");
    }
  } else {
    clhBytes = new Uint8Array(20);
  }
  const prefix = TEXT_ENCODER.encode("ARENA_LEDGER_TIP_V2_1");
  const payload = new Uint8Array(prefix.length + 8 + 20 + 8 + 32 + 32);
  let pos = 0;
  payload.set(prefix, pos);
  pos += prefix.length;
  writeU64BE(BigInt(chainId), payload, pos);
  pos += 8;
  payload.set(clhBytes, pos);
  pos += 20;
  writeU64BE(BigInt(walSeq), payload, pos);
  pos += 8;
  payload.set(chBytes, pos);
  pos += 32;
  payload.set(srBytes, pos);
  return keccak256(payload);
}

export function recoverLedgerTipSigner(digestBytes, signatureHex) {
  if (!(digestBytes instanceof Uint8Array) || digestBytes.length !== 32) {
    throw new FeraTerraError("Expected 32-byte digestBytes");
  }
  const sig = hexToBytes(signatureHex);
  if (sig.length !== 65) {
    throw new FeraTerraError("Expected 65-byte secp256k1 signature");
  }
  const r = bytesToBigIntBE(sig.subarray(0, 32));
  const s = bytesToBigIntBE(sig.subarray(32, 64));
  const vRaw = sig[64];
  const recid = vRaw === 27 || vRaw === 28 ? vRaw - 27 : vRaw;
  if ((recid !== 0 && recid !== 1) || r < 1n || r >= SECP_N || s < 1n || s > SECP_HALF_N || r >= SECP_P) {
    throw new FeraTerraError("Invalid or malleable secp256k1 signature parameters");
  }
  const ySq = mod(modPow(r, 3n, SECP_P) + 7n, SECP_P);
  let y = modPow(ySq, SECP_SQRT_EXP, SECP_P);
  if ((y * y) % SECP_P !== ySq) {
    throw new FeraTerraError("Signature r does not lie on secp256k1");
  }
  if (Number(y & 1n) !== recid) {
    y = SECP_P - y;
  }
  const rInv = modInv(r, SECP_N);
  const e = bytesToBigIntBE(digestBytes) % SECP_N;
  const u1 = mod((SECP_N - e) * rInv, SECP_N);
  const u2 = (s * rInv) % SECP_N;
  const q = secpPointAdd(secpScalarMul(u1, [SECP_GX, SECP_GY]), secpScalarMul(u2, [r, y]));
  if (q === null) {
    throw new FeraTerraError("Recovered point at infinity");
  }
  const pub64 = new Uint8Array(64);
  pub64.set(bigIntToBytes32BE(q[0]), 0);
  pub64.set(bigIntToBytes32BE(q[1]), 32);
  return formatEip55Address(keccak256(pub64).subarray(12));
}

export function verifyLedgerTip(tip, options = {}) {
  const pinnedRaw = String(options.expectedOperatorAddress || "").trim();
  try {
    const allowSelfAsserted = strictBool(options.allowSelfAssertedSigner, true);
    const tipDomain = String(tip?.tip_domain || "").trim();
    if (tipDomain && tipDomain !== "ARENA_LEDGER_TIP_V2_1") {
      return {
        valid: false,
        digest_verified: false,
        signature_verified: false,
        pinned_operator_checked: Boolean(pinnedRaw),
        computed_digest: null,
        recovered_operator_address: null,
        reason: `unsupported_tip_domain:${tipDomain}`,
      };
    }
    const walSeq = BigInt(tip?.wal_seq ?? -1);
    if (walSeq < 0n) {
      throw new FeraTerraError("wal_seq must be >= 0");
    }
    const chainId = Number(tip?.chain_id ?? 0);
    if (options.expectedChainId !== undefined && chainId !== Number(options.expectedChainId)) {
      return {
        valid: false,
        digest_verified: false,
        signature_verified: false,
        pinned_operator_checked: Boolean(pinnedRaw),
        computed_digest: null,
        recovered_operator_address: null,
        reason: "chain_id_mismatch",
      };
    }
    const clearinghouseAddress = String(tip?.clearinghouse_address || "").trim();
    if (options.expectedClearinghouseAddress) {
      const expCh = bytesToHex(hexToBytes(options.expectedClearinghouseAddress));
      const gotCh = clearinghouseAddress ? bytesToHex(hexToBytes(clearinghouseAddress)) : "";
      if (!gotCh || expCh !== gotCh) {
        return {
          valid: false,
          digest_verified: false,
          signature_verified: false,
          pinned_operator_checked: Boolean(pinnedRaw),
          computed_digest: null,
          recovered_operator_address: null,
          reason: "clearinghouse_address_mismatch",
        };
      }
    }

    const digestBytes = computeLedgerTipDigest({
      walSeq,
      ledgerChainHash: String(tip?.ledger_chain_hash || ""),
      stateRoot: String(tip?.state_root || ""),
      chainId,
      clearinghouseAddress,
    });
    const computedDigestHex = `0x${bytesToHex(digestBytes)}`;
    let digestVerified = true;
    if (tip?.tip_digest !== undefined && tip?.tip_digest !== null && String(tip.tip_digest).trim() !== "") {
      const providedDigestHex = `0x${bytesToHex(hexToBytes(String(tip.tip_digest)))}`;
      digestVerified = providedDigestHex === computedDigestHex;
    }
    if (!digestVerified) {
      return {
        valid: false,
        digest_verified: false,
        signature_verified: false,
        pinned_operator_checked: Boolean(pinnedRaw),
        computed_digest: computedDigestHex,
        recovered_operator_address: null,
        reason: "tip_digest_mismatch",
      };
    }

    let expectedLower = "";
    if (pinnedRaw) {
      const expBytes = hexToBytes(pinnedRaw);
      if (expBytes.length !== 20 || expBytes.every((b) => b === 0)) {
        return {
          valid: false,
          digest_verified: true,
          signature_verified: false,
          pinned_operator_checked: true,
          computed_digest: computedDigestHex,
          recovered_operator_address: null,
          reason: "invalid_expected_operator_address",
        };
      }
      expectedLower = `0x${bytesToHex(expBytes)}`;
      if (tip?.operator_eth_address) {
        const payloadLower = `0x${bytesToHex(hexToBytes(String(tip.operator_eth_address)))}`;
        if (payloadLower !== expectedLower) {
          return {
            valid: false,
            digest_verified: true,
            signature_verified: false,
            pinned_operator_checked: true,
            computed_digest: computedDigestHex,
            recovered_operator_address: null,
            reason: "operator_address_mismatch",
          };
        }
      }
    } else if (allowSelfAsserted) {
      const payloadBytes = hexToBytes(String(tip?.operator_eth_address || ""));
      if (payloadBytes.length !== 20 || payloadBytes.every((b) => b === 0)) {
        return {
          valid: false,
          digest_verified: true,
          signature_verified: false,
          pinned_operator_checked: false,
          computed_digest: computedDigestHex,
          recovered_operator_address: null,
          reason: "missing_operator_eth_address",
        };
      }
      expectedLower = `0x${bytesToHex(payloadBytes)}`;
    } else {
      return {
        valid: false,
        digest_verified: true,
        signature_verified: false,
        pinned_operator_checked: false,
        computed_digest: computedDigestHex,
        recovered_operator_address: null,
        reason: "self_asserted_signer_disallowed",
      };
    }

    const recovered = recoverLedgerTipSigner(digestBytes, String(tip?.operator_signature || ""));
    const sigOk = recovered.toLowerCase() === expectedLower;
    return {
      valid: sigOk,
      digest_verified: true,
      signature_verified: sigOk,
      pinned_operator_checked: Boolean(pinnedRaw),
      computed_digest: computedDigestHex,
      recovered_operator_address: recovered,
      ...(sigOk ? {} : { reason: "ecrecover_signer_mismatch" }),
    };
  } catch (err) {
    return {
      valid: false,
      digest_verified: false,
      signature_verified: false,
      pinned_operator_checked: Boolean(pinnedRaw),
      computed_digest: null,
      recovered_operator_address: null,
      reason: err instanceof Error ? err.message : String(err),
    };
  }
}

export function computeHmacSignature(apiSecret, timestampMs, method, pathAndQuery, body = "") {
  const canonical = `${String(timestampMs)}\n${String(method).toUpperCase()}\n${String(pathAndQuery)}\n${String(body)}`;
  return createHmac("sha256", String(apiSecret)).update(canonical, "utf8").digest("hex");
}

let lastHmacTimestampMs = 0;
let hmacNonceSeq = 0;

export function buildHmacHeaders({
  apiKey,
  apiSecret,
  method,
  pathAndQuery,
  body = "",
  timestampMs,
  nonce,
}) {
  if (!apiKey || !apiSecret) {
    throw new FeraTerraError("Both apiKey and apiSecret are required for HMAC-SHA256 authentication");
  }
  let effTsMs;
  if (timestampMs !== undefined && timestampMs !== null && String(timestampMs) !== "") {
    effTsMs = String(timestampMs);
  } else {
    const now = Date.now();
    const nextTs = now > lastHmacTimestampMs ? now : lastHmacTimestampMs + 1;
    lastHmacTimestampMs = nextTs;
    effTsMs = String(nextTs);
  }
  hmacNonceSeq += 1;
  const effNonce =
    nonce !== undefined && nonce !== null && String(nonce) !== ""
      ? String(nonce)
      : `${effTsMs}_${hmacNonceSeq}_${randomBytes(8).toString("hex")}`;
  const sig = computeHmacSignature(apiSecret, effTsMs, method, pathAndQuery, body);
  return {
    "X-Arena-API-Key": String(apiKey),
    "X-Arena-Timestamp": effTsMs,
    "X-Arena-Nonce": effNonce,
    "X-Arena-Signature": sig,
  };
}

function canonicalMarketKind(rawKind) {
  const k = String(rawKind || "").trim().toLowerCase();
  if (k === "perp" || k === "linear_perp" || k === "linear_perpetual") {
    return "perp";
  }
  if (k === "formula_perp" || k === "formula_perpetual") {
    return "formula_perp";
  }
  if (k === "spread" || k === "spread_book") {
    return "spread_book";
  }
  return k;
}

function unifiedSymbolForMarket(market) {
  if (typeof market?.unified_symbol === "string" && market.unified_symbol.trim()) {
    return market.unified_symbol.trim();
  }
  const rawSym = String(market?.symbol || "").trim().toUpperCase();
  const spotMatch = /^([A-Z0-9]+)-([A-Z0-9]+)-SPOT$/.exec(rawSym);
  if (spotMatch) {
    return `${spotMatch[1]}/${spotMatch[2]}`;
  }
  const perpMatch = /^([A-Z0-9]+)-([A-Z0-9]+)-(?:PERP|PRP)$/.exec(rawSym);
  if (perpMatch) {
    return `${perpMatch[1]}/${perpMatch[2]}:${perpMatch[2]}`;
  }
  const kind = canonicalMarketKind(market?.kind);
  if (kind === "perp" || kind === "formula_perp") {
    return rawSym.includes(":") ? rawSym : `${rawSym}:USD`;
  }
  return rawSym;
}

function normalizeOrderSide(rawSide, allowEmpty = false) {
  const s = String(rawSide ?? "").trim().toLowerCase();
  if (!s && allowEmpty) return "";
  if (s === "buy" || s === "bid") return "bid";
  if (s === "sell" || s === "ask") return "ask";
  throw new FeraTerraError(`Unsupported order side: ${String(rawSide)}`);
}

export class FeraTerraClient {
  constructor(options = {}) {
    const rawUrl =
      options.baseUrl ??
      process.env.FERATERRA_API_URL ??
      process.env.ARENA_URL ??
      DEFAULT_FERATERRA_API_URL;
    const candidateUrl = String(rawUrl || DEFAULT_FERATERRA_API_URL).trim() || DEFAULT_FERATERRA_API_URL;
    this.baseUrl = validateEndpointUrl(candidateUrl, "baseUrl");
    this._apiKey = String(
      options.apiKey ?? process.env.FERATERRA_API_KEY ?? process.env.ARENA_API_KEY ?? ""
    ).trim();
    this._apiSecret = String(
      options.apiSecret ?? process.env.FERATERRA_API_SECRET ?? process.env.ARENA_API_SECRET ?? ""
    ).trim();
    if (Boolean(this._apiKey) !== Boolean(this._apiSecret)) {
      throw new FeraTerraError("Both apiKey and apiSecret must be provided together when configuring HMAC auth");
    }
    const rawAid =
      options.accountId ??
      process.env.FERATERRA_ACCOUNT_ID ??
      process.env.ARENA_ACCOUNT_ID ??
      0;
    const parsedAid = Number(rawAid);
    this.accountId = Number.isFinite(parsedAid) && parsedAid >= 0 ? Math.trunc(parsedAid) : 0;
    this.expectedOperatorAddress = String(
      options.expectedOperatorAddress ??
        process.env.FERATERRA_EXPECTED_OPERATOR ??
        process.env.ARENA_EXPECTED_OPERATOR_ADDRESS ??
        ""
    ).trim();
    this.timeoutMs = Math.max(250, Number(options.timeoutMs ?? process.env.FERATERRA_TIMEOUT_MS ?? 10_000) || 10_000);
    this.allowUnauthenticated = strictBool(options.allowUnauthenticated, false);
    this._fetch = options.fetch ?? globalThis.fetch;
    if (typeof this._fetch !== "function") {
      throw new TypeError("Native fetch is required (Node.js >= 20) or pass options.fetch");
    }
  }

  hasCredentials() {
    return Boolean(this._apiKey && this._apiSecret);
  }

  _requireAuth(endpointLabel) {
    if (!this.hasCredentials() && !this.allowUnauthenticated) {
      throw new FeraTerraError(
        `HMAC-SHA256 credentials (FERATERRA_API_KEY and FERATERRA_API_SECRET) are required for ${endpointLabel}`
      );
    }
  }

  _resolveAccountId(explicitAccountId, { allowZero = false, endpointLabel = "request" } = {}) {
    if (allowZero && (explicitAccountId === 0 || explicitAccountId === "0")) {
      return 0;
    }
    const fallbackAid =
      allowZero && !this.hasCredentials() && !this.allowUnauthenticated ? 0 : this.accountId ?? 0;
    const raw = explicitAccountId ?? fallbackAid;
    const aid = Math.trunc(Number(raw));
    if (!Number.isFinite(aid) || (allowZero ? aid < 0 : aid <= 0)) {
      throw new FeraTerraError(
        allowZero
          ? `accountId must be >= 0 for ${endpointLabel}`
          : `accountId must be > 0 for ${endpointLabel} (pass accountId or set FERATERRA_ACCOUNT_ID)`
      );
    }
    return aid;
  }

  _buildHeaders(method, pathAndQuery, bodyStr = "", { skipAuth = false } = {}) {
    const headers = {
      Accept: "application/json",
    };
    if (bodyStr) {
      headers["Content-Type"] = "application/json";
    }
    if (!skipAuth && this._apiKey && this._apiSecret) {
      Object.assign(
        headers,
        buildHmacHeaders({
          apiKey: this._apiKey,
          apiSecret: this._apiSecret,
          method,
          pathAndQuery,
          body: bodyStr,
        })
      );
    }
    return headers;
  }

  async _requestJson(method, path, { query, body, skipAuth = false } = {}) {
    let pathAndQuery = path;
    if (query) {
      const qs = new URLSearchParams();
      for (const [k, v] of Object.entries(query)) {
        if (v !== undefined && v !== null && String(v) !== "") {
          qs.set(k, String(v));
        }
      }
      const qsStr = qs.toString();
      if (qsStr) {
        pathAndQuery += `?${qsStr}`;
      }
    }
    const bodyStr = body !== undefined ? JSON.stringify(body) : "";
    const url = `${this.baseUrl}${pathAndQuery}`;
    const upperMethod = String(method).toUpperCase();
    const init = {
      method: upperMethod,
      headers: this._buildHeaders(upperMethod, pathAndQuery, bodyStr, { skipAuth }),
      redirect: "error",
    };
    if (bodyStr) {
      init.body = bodyStr;
    }
    if (typeof AbortSignal !== "undefined" && typeof AbortSignal.timeout === "function") {
      init.signal = AbortSignal.timeout(this.timeoutMs);
    }
    let resp;
    try {
      resp = await this._fetch(url, init);
    } catch (err) {
      if (err instanceof FeraTerraError) {
        throw err;
      }
      throw new FeraTerraError(
        `${upperMethod} ${pathAndQuery} request failed: ${err instanceof Error ? err.message : String(err)}`,
        { code: "fetch_failed" }
      );
    }
    if (resp.status >= 300 && resp.status < 400) {
      throw new FeraTerraError(
        `${upperMethod} ${pathAndQuery} blocked HTTP redirect (HTTP ${resp.status})`,
        { status: resp.status, code: "redirect_disallowed" }
      );
    }
    const rawText = await readResponseTextBounded(resp, MAX_RESPONSE_BYTES);
    let parsed;
    try {
      parsed = rawText ? JSON.parse(rawText) : {};
    } catch {
      throw new FeraTerraError(
        `${upperMethod} ${pathAndQuery} returned non-JSON response (HTTP ${resp.status})`,
        { status: resp.status }
      );
    }
    if (!resp.ok || (parsed && typeof parsed === "object" && parsed.ok === false)) {
      const detail = parsed?.error || parsed?.message || `HTTP ${resp.status}`;
      throw new FeraTerraError(`${upperMethod} ${pathAndQuery} failed: ${String(detail)}`, {
        status: resp.status,
        code: typeof parsed?.error === "string" ? parsed.error : undefined,
      });
    }
    return parsed;
  }

  async _resolveMarket({ marketId, symbol } = {}) {
    const listed = await this.listMarkets({ activeOnly: false });
    const markets = listed.markets;
    if (marketId !== undefined && Number(marketId) > 0) {
      const targetId = Math.trunc(Number(marketId));
      const byId = markets.find((m) => Number(m.market_id) === targetId);
      if (byId) return byId;
      return {
        market_id: targetId,
        symbol: `MARKET-${targetId}`,
        unified_symbol: `MARKET-${targetId}`,
        kind: "perp",
        trading_status: "live",
        mark_price_ticks: 0,
        best_bid_ticks: 0,
        best_ask_ticks: 0,
        mark_price_usd: "0.00",
        best_bid_usd: "0.00",
        best_ask_usd: "0.00",
      };
    }
    const raw = String(symbol || "BTC-USD-PERP").trim().toUpperCase();
    if (/^\d+$/.test(raw)) {
      const numId = Number.parseInt(raw, 10);
      const byId = markets.find((m) => Number(m.market_id) === numId);
      if (byId) return byId;
    }
    const exact = markets.find(
      (m) => m.symbol.toUpperCase() === raw || m.unified_symbol.toUpperCase() === raw
    );
    if (exact) return exact;

    const baseMatch = markets.find(
      (m) =>
        m.symbol.toUpperCase().startsWith(`${raw}-`) ||
        m.unified_symbol.toUpperCase().startsWith(`${raw}/`)
    );
    if (baseMatch) return baseMatch;
    throw new FeraTerraError(`Unknown FeraTerra market: ${String(symbol || marketId)}`);
  }

  async getHealth() {
    return this._requestJson("GET", "/health", { skipAuth: true });
  }

  async getManifest() {
    return this._requestJson("GET", "/", { skipAuth: true });
  }

  async getTerms() {
    return this._requestJson("GET", "/terms", { skipAuth: true });
  }

  async getHealthAndManifest(params = {}) {
    const includeTerms = strictBool(params.includeTerms ?? params.include_terms, false);
    const [health, manifest, terms] = await Promise.all([
      this.getHealth(),
      this.getManifest(),
      includeTerms ? this.getTerms() : Promise.resolve(null),
    ]);
    return {
      ok: Boolean(
        health?.ok !== false &&
          manifest?.ok !== false &&
          (terms === null || terms?.ok !== false)
      ),
      healthy: Boolean(
        health?.ok !== false &&
          health?.conservation_ok !== false &&
          health?.double_entry_ok !== false
      ),
      wal_seq: Number(health?.wal_seq ?? manifest?.wal_seq ?? 0),
      chain_id: Number(manifest?.chain_id ?? terms?.chain_id ?? 0),
      clearinghouse_address: String(
        manifest?.clearinghouse_address ?? terms?.clearinghouse_address ?? ""
      ),
      health,
      manifest,
      ...(terms !== null ? { terms } : {}),
    };
  }

  async listMarkets(params = {}) {
    const activeOnly = strictBool(params.activeOnly ?? params.active_only, true);
    const resp = await this._requestJson("GET", "/markets");
    const kindFilter = canonicalMarketKind(params.kind || "");
    const symbolFilter = String(params.symbol || "").trim().toUpperCase();
    const rawMarkets = Array.isArray(resp.markets) ? resp.markets : [];
    const markets = [];
    for (const m of rawMarkets) {
      if (kindFilter && canonicalMarketKind(m.kind) !== kindFilter) {
        continue;
      }
      if (activeOnly && String(m.trading_status || "live").toLowerCase() === "halted") {
        continue;
      }
      const unified = unifiedSymbolForMarket(m);
      if (
        symbolFilter &&
        String(m.symbol || "").toUpperCase() !== symbolFilter &&
        unified.toUpperCase() !== symbolFilter
      ) {
        continue;
      }
      const markTicks = Number(m.mark_price_ticks ?? 0);
      const bidTicks = Number(m.best_bid_ticks ?? 0);
      const askTicks = Number(m.best_ask_ticks ?? 0);
      markets.push({
        ...m,
        market_id: Number(m.market_id),
        symbol: String(m.symbol || ""),
        unified_symbol: unified,
        kind: String(m.kind || ""),
        trading_status: String(m.trading_status || "live"),
        mark_price_ticks: markTicks,
        best_bid_ticks: bidTicks,
        best_ask_ticks: askTicks,
        mark_price_usd: ticksToUsd(markTicks),
        best_bid_usd: ticksToUsd(bidTicks),
        best_ask_usd: ticksToUsd(askTicks),
      });
    }
    return {
      ok: true,
      wal_seq: Number(resp.wal_seq ?? 0),
      count: markets.length,
      markets,
    };
  }

  async getOrderbook(params = {}) {
    const depth = Math.max(1, Math.min(200, Math.trunc(Number(params.depth ?? 20) || 20)));
    const rawMid = params.marketId ?? params.market_id;
    let marketId = rawMid !== undefined && Number(rawMid) > 0 ? Math.trunc(Number(rawMid)) : 0;
    let symbol = String(params.symbol || "").trim();
    let unifiedSymbol = symbol;
    if (marketId <= 0) {
      const mkt = await this._resolveMarket({ symbol: symbol || "BTC-USD-PERP" });
      marketId = mkt.market_id;
      symbol = mkt.symbol;
      unifiedSymbol = mkt.unified_symbol;
    }
    const book = await this._requestJson("GET", "/book", {
      query: { market_id: marketId, depth },
    });
    const resolvedSymbol = String(book.symbol || symbol || `MARKET-${marketId}`);
    const resolvedUnified = unifiedSymbolForMarket({
      symbol: resolvedSymbol,
      unified_symbol: book.unified_symbol || unifiedSymbol,
      kind: book.kind,
    });
    const normalizeSide = (levels) =>
      (Array.isArray(levels) ? levels : []).map((lvl) => {
        if (Array.isArray(lvl)) {
          const pxTicks = Number(lvl[0] ?? 0);
          const qtyLots = Number(lvl[1] ?? 0);
          const count = Number(lvl[2] ?? 1);
          return {
            price_ticks: pxTicks,
            price_usd: ticksToUsd(pxTicks),
            qty_lots: qtyLots,
            qty_base: lotsToBase(qtyLots),
            order_count: count,
          };
        }
        const pxTicks = Number(lvl?.price_ticks ?? 0);
        const qtyLots = Number(lvl?.qty_lots ?? 0);
        const count = Number(lvl?.order_count ?? 1);
        return {
          price_ticks: pxTicks,
          price_usd: ticksToUsd(pxTicks),
          qty_lots: qtyLots,
          qty_base: lotsToBase(qtyLots),
          order_count: count,
        };
      });

    const formattedBids = normalizeSide(book.bids);
    const formattedAsks = normalizeSide(book.asks);
    const bestBidTicks = formattedBids.length > 0 ? formattedBids[0].price_ticks : null;
    const bestAskTicks = formattedAsks.length > 0 ? formattedAsks[0].price_ticks : null;
    const spreadUsd =
      bestBidTicks !== null && bestAskTicks !== null && bestAskTicks >= bestBidTicks
        ? ticksToUsd(bestAskTicks - bestBidTicks)
        : null;

    return {
      ...book,
      ok: true,
      wal_seq: Number(book.wal_seq ?? 0),
      market_id: Number(book.market_id ?? marketId),
      symbol: resolvedSymbol,
      unified_symbol: resolvedUnified,
      depth,
      best_bid_usd: bestBidTicks !== null ? ticksToUsd(bestBidTicks) : null,
      best_ask_usd: bestAskTicks !== null ? ticksToUsd(bestAskTicks) : null,
      spread_usd: spreadUsd,
      bids: Array.isArray(book.bids) ? book.bids : [],
      asks: Array.isArray(book.asks) ? book.asks : [],
      formatted_bids: formattedBids,
      formatted_asks: formattedAsks,
    };
  }

  async getTrades(params = {}) {
    const limit = Math.max(1, Math.min(512, Math.trunc(Number(params.limit ?? 50) || 50)));
    const rawMid = params.marketId ?? params.market_id;
    let marketId = rawMid !== undefined && Number(rawMid) > 0 ? Math.trunc(Number(rawMid)) : 0;
    let symbol = String(params.symbol || "").trim();
    let unifiedSymbol = symbol;
    if (marketId <= 0) {
      const mkt = await this._resolveMarket({ symbol: symbol || "BTC-USD-PERP" });
      marketId = mkt.market_id;
      symbol = mkt.symbol;
      unifiedSymbol = mkt.unified_symbol;
    }
    const resp = await this._requestJson("GET", "/trades", {
      query: { market_id: marketId, limit },
    });
    const rawTrades = Array.isArray(resp.trades) ? resp.trades : [];
    const trades = rawTrades.map((t) => {
      const pxTicks = Number(t?.price_ticks ?? 0);
      const qtyLots = Number(t?.qty_lots ?? 0);
      return {
        ...t,
        price_ticks: pxTicks,
        price_usd: ticksToUsd(pxTicks),
        qty_lots: qtyLots,
        qty_base: lotsToBase(qtyLots),
      };
    });
    const resolvedSymbol = String(resp.symbol || symbol || `MARKET-${marketId}`);
    return {
      ...resp,
      ok: true,
      market_id: Number(resp.market_id ?? marketId),
      symbol: resolvedSymbol,
      unified_symbol: unifiedSymbolForMarket({
        symbol: resolvedSymbol,
        unified_symbol: resp.unified_symbol || unifiedSymbol,
      }),
      count: trades.length,
      trades,
    };
  }

  async getCandles(params = {}) {
    const limit = Math.max(1, Math.min(240, Math.trunc(Number(params.limit ?? 120) || 120)));
    const interval = String(params.interval || "1m").trim() || "1m";
    if (!["tick", "1s", "1m"].includes(interval)) {
      throw new FeraTerraError(`Unsupported candle interval: ${interval} (expected tick, 1s, or 1m)`);
    }
    const rawMid = params.marketId ?? params.market_id;
    let marketId = rawMid !== undefined && Number(rawMid) > 0 ? Math.trunc(Number(rawMid)) : 0;
    let symbol = String(params.symbol || "").trim();
    let unifiedSymbol = symbol;
    if (marketId <= 0) {
      const mkt = await this._resolveMarket({ symbol: symbol || "BTC-USD-PERP" });
      marketId = mkt.market_id;
      symbol = mkt.symbol;
      unifiedSymbol = mkt.unified_symbol;
    }
    const resp = await this._requestJson("GET", "/candles", {
      query: { market_id: marketId, interval, limit },
    });
    const rawCandles = Array.isArray(resp.candles) ? resp.candles : [];
    const candles = rawCandles.map((c) => {
      const openTicks = Number(c?.open_ticks ?? c?.open ?? 0);
      const highTicks = Number(c?.high_ticks ?? c?.high ?? 0);
      const lowTicks = Number(c?.low_ticks ?? c?.low ?? 0);
      const closeTicks = Number(c?.close_ticks ?? c?.close ?? 0);
      const volLots = Number(c?.volume_lots ?? c?.volume ?? 0);
      return {
        ...c,
        open_ticks: openTicks,
        high_ticks: highTicks,
        low_ticks: lowTicks,
        close_ticks: closeTicks,
        volume_lots: volLots,
        open_usd: ticksToUsd(openTicks),
        high_usd: ticksToUsd(highTicks),
        low_usd: ticksToUsd(lowTicks),
        close_usd: ticksToUsd(closeTicks),
        volume_base: lotsToBase(volLots),
      };
    });
    const resolvedSymbol = String(resp.symbol || symbol || `MARKET-${marketId}`);
    return {
      ...resp,
      ok: true,
      market_id: Number(resp.market_id ?? marketId),
      symbol: resolvedSymbol,
      unified_symbol: unifiedSymbolForMarket({
        symbol: resolvedSymbol,
        unified_symbol: resp.unified_symbol || unifiedSymbol,
      }),
      interval: String(resp.interval || interval),
      count: candles.length,
      candles,
    };
  }

  async getLeaderboard(params = {}) {
    const limit = Math.max(1, Math.min(100, Math.trunc(Number(params.limit ?? 25) || 25)));
    const sort = String(params.sort || "equity").trim().toLowerCase() || "equity";
    const resp = await this._requestJson("GET", "/leaderboard", {
      query: { limit, sort },
    });
    const entries = Array.isArray(resp.entries) ? resp.entries : [];
    return {
      ...resp,
      ok: true,
      wal_seq: Number(resp.wal_seq ?? 0),
      sort_by: String(resp.sort_by || sort),
      entries,
    };
  }

  async getLedgerTip(options = {}) {
    const expectedOp = String(
      options.expectedOperatorAddress ??
        options.expected_operator_address ??
        this.expectedOperatorAddress ??
        ""
    ).trim();
    const allowSelfAsserted = strictBool(
      options.allowSelfAssertedSigner ?? options.allow_self_asserted_signer,
      !expectedOp
    );
    const tip = await this._requestJson("GET", "/ledger/tip");
    const verification = verifyLedgerTip(tip, {
      expectedOperatorAddress: expectedOp,
      expectedChainId: options.expectedChainId ?? options.expected_chain_id,
      expectedClearinghouseAddress:
        options.expectedClearinghouseAddress ?? options.expected_clearinghouse_address,
      allowSelfAssertedSigner: allowSelfAsserted,
    });
    return {
      ...tip,
      ok: true,
      verification,
      valid: verification.valid,
      digest_verified: verification.digest_verified,
      signature_verified: verification.signature_verified,
      pinned_operator_checked: verification.pinned_operator_checked,
      computed_digest: verification.computed_digest,
      recovered_operator_address: verification.recovered_operator_address,
      ...(verification.reason ? { reason: verification.reason } : {}),
    };
  }

  async verifySolvency(params = {}) {
    const includeHealth = strictBool(params.includeHealth ?? params.include_health, true);
    const expectedOp = String(
      params.expectedOperatorAddress ??
        params.expected_operator_address ??
        this.expectedOperatorAddress ??
        ""
    ).trim();
    const allowSelfAsserted = strictBool(
      params.allowSelfAssertedSigner ?? params.allow_self_asserted_signer,
      !expectedOp
    );
    const [tip, health] = await Promise.all([
      this._requestJson("GET", "/ledger/tip"),
      includeHealth ? this._requestJson("GET", "/health") : Promise.resolve(null),
    ]);

    const verification = verifyLedgerTip(tip, {
      expectedOperatorAddress: expectedOp,
      expectedChainId: params.expectedChainId ?? params.expected_chain_id,
      expectedClearinghouseAddress:
        params.expectedClearinghouseAddress ?? params.expected_clearinghouse_address,
      allowSelfAssertedSigner: allowSelfAsserted,
    });

    const conservationOk =
      health === null
        ? true
        : health.ok !== false &&
          health.conservation_ok !== false &&
          health.double_entry_ok !== false;

    const solvent = Boolean(verification.signature_verified && verification.digest_verified && conservationOk);

    return {
      ok: true,
      solvent,
      signature_verified: verification.signature_verified,
      digest_verified: verification.digest_verified,
      conservation_ok: conservationOk,
      pinned_operator_checked: verification.pinned_operator_checked,
      recovered_operator_address: verification.recovered_operator_address,
      operator_eth_address: tip.operator_eth_address ? String(tip.operator_eth_address) : null,
      wal_seq: Number(tip.wal_seq ?? 0),
      state_root: String(tip.state_root || ""),
      ledger_chain_hash: String(tip.ledger_chain_hash || ""),
      tip_digest: tip.tip_digest ? String(tip.tip_digest) : verification.computed_digest,
      chain_id: Number(tip.chain_id ?? 0),
      clearinghouse_address: String(tip.clearinghouse_address || ""),
      ...(verification.reason ? { reason: verification.reason } : {}),
      health,
      tip,
    };
  }

  _buildOrderPayload(params, { accountId, mkt, defaultAmountBase }) {
    const side = normalizeOrderSide(params.side || "buy");
    const isMarket =
      strictBool(params.isMarket ?? params.is_market, false) ||
      String(params.orderType ?? params.order_type ?? "limit").trim().toLowerCase() === "market";

    const rawQtyLots = params.qtyLots ?? params.qty_lots;
    const rawAmount = params.amount ?? params.amountBase ?? params.amount_base ?? defaultAmountBase;
    const qtyLots =
      rawQtyLots !== undefined && rawQtyLots !== null
        ? Math.trunc(Number(rawQtyLots))
        : baseToLots(rawAmount);
    if (!Number.isFinite(qtyLots) || qtyLots <= 0) {
      throw new FeraTerraError("Order quantity (qtyLots or amount) must be > 0");
    }

    const primaryPeg = strictBool(params.primaryPeg ?? params.primary_peg, false);
    const midpointPeg = strictBool(params.midpointPeg ?? params.midpoint_peg, false);
    const markPeg = strictBool(params.markPeg ?? params.mark_peg, false);
    const trailingPeg = strictBool(params.trailingPeg ?? params.trailing_peg, false);
    const darkMidpoint = strictBool(params.darkMidpoint ?? params.dark_midpoint, false);
    const isPegged = primaryPeg || midpointPeg || markPeg || trailingPeg || darkMidpoint;
    const isSpread = canonicalMarketKind(mkt?.kind) === "spread_book";
    const rawDiffUsd = params.differentialUsd ?? params.differential_usd;
    const rawPriceTicks = params.priceTicks ?? params.price_ticks;
    const rawPriceUsd = params.price ?? params.priceUsd ?? params.price_usd;

    let priceTicks;
    if (isSpread && rawDiffUsd !== undefined && rawDiffUsd !== null) {
      const offsetTicks = Number(mkt?.offset_ticks ?? 1_000_000);
      priceTicks = offsetTicks + usdToTicks(rawDiffUsd);
    } else if (rawPriceTicks !== undefined && rawPriceTicks !== null) {
      priceTicks = Math.trunc(Number(rawPriceTicks));
    } else if (rawPriceUsd !== undefined && rawPriceUsd !== null) {
      priceTicks = usdToTicks(rawPriceUsd);
    } else if (isMarket || isPegged) {
      priceTicks = 0;
    } else {
      priceTicks = Number(mkt?.mark_price_ticks || mkt?.best_ask_ticks || mkt?.best_bid_ticks || 0);
    }
    if (!Number.isFinite(priceTicks) || (!isMarket && !isPegged && !isSpread && priceTicks <= 0)) {
      throw new FeraTerraError("Limit order requires a positive price or priceTicks");
    }

    let tif = String(params.tif || (isMarket ? "ioc" : "gtc")).trim().toLowerCase();
    const postOnly = strictBool(params.postOnly ?? params.post_only, false);
    if (postOnly && tif === "gtc") {
      tif = "post_only";
    }
    const stp = String(params.stp || "cancel_resting").trim().toLowerCase();
    const reduceOnly = strictBool(params.reduceOnly ?? params.reduce_only, false);

    const payload = {
      account_id: accountId,
      market_id: mkt.market_id,
      side,
      tif,
      stp,
      price_ticks: priceTicks,
      qty_lots: qtyLots,
      reduce_only: reduceOnly,
      is_market: isMarket,
    };

    const optBools = [
      ["post_only_slide", strictBool(params.postOnlySlide ?? params.post_only_slide, false)],
      ["primary_peg", primaryPeg],
      ["midpoint_peg", midpointPeg],
      ["mark_peg", markPeg],
      ["trailing_peg", trailingPeg],
      ["dark_midpoint", darkMidpoint],
      ["margin_spot", strictBool(params.marginSpot ?? params.margin_spot, false)],
      ["oco_linked", strictBool(params.ocoLinked ?? params.oco_linked, false)],
      ["stp_decrement_and_cancel", strictBool(params.stpDecrementAndCancel ?? params.stp_decrement_and_cancel, false)],
    ];
    for (const [k, v] of optBools) {
      if (v) payload[k] = true;
    }

    const optPositiveInts = [
      ["min_qty_lots", params.minQtyLots ?? params.min_qty_lots],
      ["display_qty_lots", params.displayQtyLots ?? params.display_qty_lots],
      ["auto_skew_ticks", params.autoSkewTicks ?? params.auto_skew_ticks],
      ["auto_flip_ticks", params.autoFlipTicks ?? params.auto_flip_ticks],
      ["max_lifetime_wal_seqs", params.maxLifetimeWalSeqs ?? params.max_lifetime_wal_seqs],
      ["jit_elastic_mult", params.jitElasticMult ?? params.jit_elastic_mult],
      ["client_tag", params.clientTag ?? params.client_tag],
      ["priority_fee_ppm", params.priorityFeePpm ?? params.priority_fee_ppm],
    ];
    for (const [k, v] of optPositiveInts) {
      if (v !== undefined && v !== null && Number(v) > 0) {
        payload[k] = Math.trunc(Number(v));
      }
    }
    const pegOff = params.pegOffsetTicks ?? params.peg_offset_ticks;
    if (pegOff !== undefined && pegOff !== null && Number(pegOff) !== 0) {
      payload.peg_offset_ticks = Math.trunc(Number(pegOff));
    }

    return { payload, side, qtyLots, priceTicks, isMarket };
  }

  async previewOrder(params = {}) {
    const accountId = this._resolveAccountId(params.accountId ?? params.account_id, {
      allowZero: true,
      endpointLabel: "previewOrder",
    });
    const rawMid = params.marketId ?? params.market_id;
    const rawDiffUsd = params.differentialUsd ?? params.differential_usd;
    const isMarketPreview = strictBool(params.isMarket ?? params.is_market, false);
    const hasExplicitPriceOrMkt =
      rawDiffUsd === undefined &&
      (params.priceTicks !== undefined ||
        params.price_ticks !== undefined ||
        params.price !== undefined ||
        params.priceUsd !== undefined ||
        params.price_usd !== undefined ||
        isMarketPreview ||
        String(params.orderType ?? params.order_type ?? "").trim().toLowerCase() === "market");

    let mkt;
    if (rawMid !== undefined && Number(rawMid) > 0 && hasExplicitPriceOrMkt) {
      const mid = Math.trunc(Number(rawMid));
      mkt = {
        market_id: mid,
        symbol: String(params.symbol || `MARKET-${mid}`),
        unified_symbol: unifiedSymbolForMarket({ symbol: params.symbol || `MARKET-${mid}` }),
        kind: "perp",
        mark_price_ticks: 0,
        best_bid_ticks: 0,
        best_ask_ticks: 0,
      };
    } else {
      mkt = await this._resolveMarket({
        marketId: rawMid,
        symbol: params.symbol || "BTC-USD-PERP",
      });
    }

    const { payload, side, qtyLots, priceTicks } = this._buildOrderPayload(params, {
      accountId,
      mkt,
      defaultAmountBase: 0.01,
    });

    const resp = await this._requestJson("POST", "/order/preview", {
      body: payload,
      skipAuth: accountId === 0,
    });
    const effPxTicks = Number(resp.effective_price_ticks ?? priceTicks);
    const estFilledLots = Number(resp.estimated_filled_lots ?? 0);
    const estRestingLots = Number(resp.estimated_resting_lots ?? 0);
    const estAvgPxTicks = Number(resp.estimated_avg_price_ticks ?? 0);
    const estFeeMicro = Number(resp.estimated_fee_micro ?? resp.estimated_net_fee_micro ?? 0);
    const preImrMicro = Number(resp.pre_imr_micro ?? 0);
    const postImrMicro = Number(resp.post_imr_micro ?? 0);
    const imrDeltaMicro = Number(resp.imr_delta_micro ?? postImrMicro - preImrMicro);
    const postMmrMicro = Number(resp.post_mmr_micro ?? 0);
    const postFreeMicro = Number(resp.post_free_margin_micro ?? 0);
    const wouldAccept = strictBool(resp.would_accept ?? resp.wouldAccept, false);

    return {
      ...resp,
      ok: true,
      preview: true,
      stateless_zero_key: accountId === 0,
      account_id: Number(resp.account_id ?? accountId),
      would_accept: wouldAccept,
      status: String(resp.status || (wouldAccept ? "Ok" : "Rejected")),
      market_id: mkt.market_id,
      symbol: mkt.symbol,
      unified_symbol: mkt.unified_symbol,
      side,
      qty_lots: qtyLots,
      qty_base: lotsToBase(qtyLots),
      effective_price_ticks: effPxTicks,
      effective_price_usd: ticksToUsd(effPxTicks),
      estimated_filled_lots: estFilledLots,
      estimated_filled_base: lotsToBase(estFilledLots),
      estimated_resting_lots: estRestingLots,
      estimated_resting_base: lotsToBase(estRestingLots),
      estimated_avg_price_ticks: estAvgPxTicks,
      estimated_avg_price_usd: ticksToUsd(estAvgPxTicks),
      estimated_fee_micro: estFeeMicro,
      estimated_net_fee_micro: estFeeMicro,
      estimated_fee_usd: microToUsd(estFeeMicro),
      pre_imr_micro: preImrMicro,
      pre_imr_usd: microToUsd(preImrMicro),
      post_imr_micro: postImrMicro,
      post_imr_usd: microToUsd(postImrMicro),
      imr_delta_micro: imrDeltaMicro,
      imr_delta_usd: microToUsd(imrDeltaMicro),
      post_mmr_micro: postMmrMicro,
      post_mmr_usd: microToUsd(postMmrMicro),
      post_free_margin_micro: postFreeMicro,
      post_free_margin_usd: microToUsd(postFreeMicro),
      wal_seq: Number(resp.wal_seq ?? 0),
    };
  }

  async getAccount(params = {}) {
    this._requireAuth("GET /account");
    const accountId = this._resolveAccountId(params.accountId ?? params.account_id, {
      endpointLabel: "getAccount",
    });
    const acct = await this._requestJson("GET", "/account", {
      query: { account_id: accountId },
    });
    const totalEqMicro = Number(acct.total_equity_micro ?? acct.equity_micro ?? 0);
    const freeUsdMicro = Number(acct.free_usd_micro ?? acct.free_margin_micro ?? 0);
    const withdrawableMicro = Number(acct.withdrawable_usd_micro ?? freeUsdMicro);
    const imrMicro = Number(acct.imr_micro ?? 0);
    const mmrMicro = Number(acct.mmr_micro ?? 0);
    return {
      ...acct,
      ok: true,
      account_id: Number(acct.account_id ?? accountId),
      total_equity_usd: microToUsd(totalEqMicro),
      free_usd: microToUsd(freeUsdMicro),
      withdrawable_usd: microToUsd(withdrawableMicro),
      imr_usd: microToUsd(imrMicro),
      mmr_usd: microToUsd(mmrMicro),
    };
  }

  async placeOrder(params = {}) {
    this._requireAuth("POST /order");
    const accountId = this._resolveAccountId(params.accountId ?? params.account_id, {
      endpointLabel: "placeOrder",
    });
    const rawMid = params.marketId ?? params.market_id;
    const isMarketPlace = strictBool(params.isMarket ?? params.is_market, false);
    const hasExplicitPriceOrMkt =
      params.priceTicks !== undefined ||
      params.price_ticks !== undefined ||
      params.price !== undefined ||
      params.priceUsd !== undefined ||
      params.price_usd !== undefined ||
      isMarketPlace ||
      String(params.orderType ?? params.order_type ?? "").trim().toLowerCase() === "market";

    let mkt;
    if (rawMid !== undefined && Number(rawMid) > 0 && hasExplicitPriceOrMkt) {
      const mid = Math.trunc(Number(rawMid));
      mkt = {
        market_id: mid,
        symbol: String(params.symbol || `MARKET-${mid}`),
        unified_symbol: unifiedSymbolForMarket({ symbol: params.symbol || `MARKET-${mid}` }),
        kind: "perp",
        mark_price_ticks: 0,
        best_bid_ticks: 0,
        best_ask_ticks: 0,
      };
    } else {
      mkt = await this._resolveMarket({
        marketId: rawMid,
        symbol: params.symbol || "BTC-USD-PERP",
      });
    }

    if (
      params.qtyLots === undefined &&
      params.qty_lots === undefined &&
      params.amount === undefined &&
      params.amountBase === undefined &&
      params.amount_base === undefined
    ) {
      throw new FeraTerraError("placeOrder requires qtyLots or amount / amountBase");
    }

    const { payload, side, qtyLots, priceTicks } = this._buildOrderPayload(params, {
      accountId,
      mkt,
      defaultAmountBase: undefined,
    });
    const resp = await this._requestJson("POST", "/order", { body: payload });
    const filledLots = Number(resp.filled_lots ?? 0);
    const restingLots = Number(resp.resting_lots ?? 0);
    return {
      ...resp,
      ok: true,
      account_id: Number(resp.account_id ?? accountId),
      market_id: Number(resp.market_id ?? mkt.market_id),
      symbol: String(resp.symbol || mkt.symbol),
      unified_symbol: mkt.unified_symbol,
      side,
      price_ticks: priceTicks,
      price_usd: ticksToUsd(priceTicks),
      qty_lots: qtyLots,
      qty_base: lotsToBase(qtyLots),
      filled_lots: filledLots,
      filled_base: lotsToBase(filledLots),
      resting_lots: restingLots,
      resting_base: lotsToBase(restingLots),
    };
  }

  async submitOrder(params = {}) {
    return this.placeOrder(params);
  }

  async replaceQuote(params = {}) {
    this._requireAuth("POST /quote");
    const accountId = this._resolveAccountId(params.accountId ?? params.account_id, {
      endpointLabel: "replaceQuote",
    });
    const rawMid = params.marketId ?? params.market_id;
    let mkt;
    if (rawMid !== undefined && Number(rawMid) > 0) {
      const mid = Math.trunc(Number(rawMid));
      mkt = {
        market_id: mid,
        symbol: String(params.symbol || `MARKET-${mid}`),
        unified_symbol: unifiedSymbolForMarket({ symbol: params.symbol || `MARKET-${mid}` }),
        kind: "perp",
      };
    } else {
      mkt = await this._resolveMarket({ symbol: params.symbol || "BTC-USD-PERP" });
    }

    const rawBidPxTicks = params.bidPriceTicks ?? params.bid_price_ticks;
    const rawBidPxUsd = params.bidPrice ?? params.bidPriceUsd ?? params.bid_price_usd;
    const bidPriceTicks =
      rawBidPxTicks !== undefined && rawBidPxTicks !== null
        ? Math.trunc(Number(rawBidPxTicks))
        : rawBidPxUsd !== undefined && rawBidPxUsd !== null
          ? usdToTicks(rawBidPxUsd)
          : 0;

    const rawAskPxTicks = params.askPriceTicks ?? params.ask_price_ticks;
    const rawAskPxUsd = params.askPrice ?? params.askPriceUsd ?? params.ask_price_usd;
    const askPriceTicks =
      rawAskPxTicks !== undefined && rawAskPxTicks !== null
        ? Math.trunc(Number(rawAskPxTicks))
        : rawAskPxUsd !== undefined && rawAskPxUsd !== null
          ? usdToTicks(rawAskPxUsd)
          : 0;

    const rawBidLots = params.bidQtyLots ?? params.bid_qty_lots;
    const rawBidBase = params.bidAmount ?? params.bidAmountBase ?? params.bid_amount_base;
    const bidQtyLots =
      rawBidLots !== undefined && rawBidLots !== null
        ? Math.trunc(Number(rawBidLots))
        : rawBidBase !== undefined && rawBidBase !== null
          ? baseToLots(rawBidBase)
          : 0;

    const rawAskLots = params.askQtyLots ?? params.ask_qty_lots;
    const rawAskBase = params.askAmount ?? params.askAmountBase ?? params.ask_amount_base;
    const askQtyLots =
      rawAskLots !== undefined && rawAskLots !== null
        ? Math.trunc(Number(rawAskLots))
        : rawAskBase !== undefined && rawAskBase !== null
          ? baseToLots(rawAskBase)
          : 0;

    if (bidQtyLots < 0 || askQtyLots < 0) {
      throw new FeraTerraError("Quote quantities must be >= 0");
    }
    const quotePegMode = Math.trunc(Number(params.quotePegMode ?? params.quote_peg_mode ?? 0) || 0);
    if (bidQtyLots > 0 && bidPriceTicks <= 0 && quotePegMode <= 0) {
      throw new FeraTerraError("Positive bid quote quantity requires positive bidPrice or bidPriceTicks");
    }
    if (askQtyLots > 0 && askPriceTicks <= 0 && quotePegMode <= 0) {
      throw new FeraTerraError("Positive ask quote quantity requires positive askPrice or askPriceTicks");
    }

    const tif = String(params.tif || "post_only").trim().toLowerCase();
    const stp = String(params.stp || "cancel_resting").trim().toLowerCase();
    const payload = {
      account_id: accountId,
      market_id: mkt.market_id,
      bid_price_ticks: bidPriceTicks,
      bid_qty_lots: bidQtyLots,
      ask_price_ticks: askPriceTicks,
      ask_qty_lots: askQtyLots,
      tif,
      stp,
    };

    if (strictBool(params.postOnlySlide ?? params.post_only_slide, false)) payload.post_only_slide = true;
    if (strictBool(params.marginSpot ?? params.margin_spot, false)) payload.margin_spot = true;
    if (strictBool(params.ocoLinked ?? params.oco_linked, false)) payload.oco_linked = true;
    if (strictBool(params.ladderByTag ?? params.ladder_by_tag, false)) payload.ladder_by_tag = true;
    if (quotePegMode > 0) payload.quote_peg_mode = quotePegMode;

    const optInts = [
      ["client_tag", params.clientTag ?? params.client_tag],
      ["auto_skew_ticks", params.autoSkewTicks ?? params.auto_skew_ticks],
      ["auto_flip_ticks", params.autoFlipTicks ?? params.auto_flip_ticks],
      ["max_lifetime_wal_seqs", params.maxLifetimeWalSeqs ?? params.max_lifetime_wal_seqs],
      ["jit_elastic_mult", params.jitElasticMult ?? params.jit_elastic_mult],
    ];
    for (const [k, v] of optInts) {
      if (v !== undefined && v !== null && Number(v) > 0) {
        payload[k] = Math.trunc(Number(v));
      }
    }
    const pegOff = params.pegOffsetTicks ?? params.peg_offset_ticks;
    if (pegOff !== undefined && pegOff !== null && Number(pegOff) !== 0) {
      payload.peg_offset_ticks = Math.trunc(Number(pegOff));
    }

    const resp = await this._requestJson("POST", "/quote", { body: payload });
    return {
      ...resp,
      ok: true,
      account_id: Number(resp.account_id ?? accountId),
      market_id: Number(resp.market_id ?? mkt.market_id),
      symbol: String(resp.symbol || mkt.symbol),
      unified_symbol: mkt.unified_symbol,
      bid_price_ticks: bidPriceTicks,
      bid_price_usd: ticksToUsd(bidPriceTicks),
      bid_qty_lots: bidQtyLots,
      bid_qty_base: lotsToBase(bidQtyLots),
      ask_price_ticks: askPriceTicks,
      ask_price_usd: ticksToUsd(askPriceTicks),
      ask_qty_lots: askQtyLots,
      ask_qty_base: lotsToBase(askQtyLots),
    };
  }

  async replaceTwoSidedQuote(params = {}) {
    return this.replaceQuote(params);
  }

  async cancelOrder(params = {}) {
    this._requireAuth("POST /cancel");
    const accountId = this._resolveAccountId(params.accountId ?? params.account_id, {
      endpointLabel: "cancelOrder",
    });
    const orderId = Math.trunc(Number(params.orderId ?? params.order_id ?? 0));
    if (!Number.isFinite(orderId) || orderId <= 0) {
      throw new FeraTerraError("orderId must be > 0 for cancelOrder");
    }
    const rawMid = params.marketId ?? params.market_id;
    let marketId = rawMid !== undefined && Number(rawMid) > 0 ? Math.trunc(Number(rawMid)) : 0;
    if (marketId <= 0) {
      if (!params.symbol) {
        throw new FeraTerraError("marketId or symbol is required for cancelOrder");
      }
      const mkt = await this._resolveMarket({ symbol: params.symbol });
      marketId = mkt.market_id;
    }
    const resp = await this._requestJson("POST", "/cancel", {
      body: {
        account_id: accountId,
        market_id: marketId,
        order_id: orderId,
      },
    });
    return {
      ...resp,
      ok: true,
      account_id: Number(resp.account_id ?? accountId),
      market_id: Number(resp.market_id ?? marketId),
      order_id: Number(resp.order_id ?? orderId),
    };
  }

  async cancelAllOrders(params = {}) {
    this._requireAuth("POST /cancel_all");
    const accountId = this._resolveAccountId(params.accountId ?? params.account_id, {
      endpointLabel: "cancelAllOrders",
    });
    const rawMid = params.marketId ?? params.market_id;
    let marketId = rawMid !== undefined && Number(rawMid) >= 0 ? Math.trunc(Number(rawMid)) : 0;
    if (marketId === 0 && params.symbol) {
      const mkt = await this._resolveMarket({ symbol: params.symbol });
      marketId = mkt.market_id;
    }
    const payload = {
      account_id: accountId,
      market_id: marketId,
      cancel_all: true,
    };
    const side = normalizeOrderSide(params.side, true);
    if (side) {
      payload.side = side;
    }
    const clientTagFilter = params.clientTagFilter ?? params.client_tag_filter;
    if (clientTagFilter !== undefined && Number(clientTagFilter) > 0) {
      payload.client_tag_filter = Math.trunc(Number(clientTagFilter));
    }
    const marketBitmask = params.marketBitmask ?? params.market_bitmask;
    if (marketBitmask !== undefined && Number(marketBitmask) > 0) {
      payload.market_bitmask = Math.trunc(Number(marketBitmask));
    }
    const resp = await this._requestJson("POST", "/cancel_all", { body: payload });
    return {
      ...resp,
      ok: true,
      account_id: Number(resp.account_id ?? accountId),
      market_id: marketId,
      canceled_count: Number(resp.canceled_count ?? resp.canceled ?? 0),
    };
  }

  async cancelAll(params = {}) {
    return this.cancelAllOrders(params);
  }
}

export default FeraTerraClient;
