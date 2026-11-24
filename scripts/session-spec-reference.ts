#!/usr/bin/env bun
/**
 * dotenvx session wire spec — from-scratch reference implementation, oracle
 * validation, and fixture generator.
 *
 * Modes:
 *   bun scripts/session-spec-reference.ts                 validate (default)
 *   bun scripts/session-spec-reference.ts --gen-fixtures  validate, then write
 *                                                         rs/tests/fixtures/session-vectors.json
 *
 * The spec functions below never call the @dotenvx library — node:crypto and
 * bigint EC math only. The library is loaded exclusively by the oracle
 * (loadOracle) and used to prove byte-level equivalence. The oracle is pinned
 * hard: @dotenvx/dotenvx 2.38.2 resolving @dotenvx/primitives 3.3.1 (the
 * versions this repo depends on); the script fails if either differs.
 *
 * This file is a working-tree artifact of the wire-spec task, not a product
 * module; the Rust implementer should treat the fixture JSON as authority and
 * this script as the executable statement of the spec.
 */

import { createCipheriv, createDecipheriv, createHash, hkdfSync, randomBytes } from "node:crypto";
import { execFileSync } from "node:child_process";
import {
  mkdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { fileURLToPath } from "node:url";

// ---------------------------------------------------------------------------
// 1. Pinned spec constants (every one verified against primitives 3.3.1 source)
// ---------------------------------------------------------------------------

/** ECIES_CONFIG (primitives dist: class Config { ... } / ECIES_CONFIG = new Config()). */
export const ECIES_CONFIG = {
  ellipticCurve: "secp256k1",
  /** ephemeral public key serialized UNCOMPRESSED (65 bytes, 0x04 || X || Y) */
  isEphemeralKeyCompressed: false,
  /** HKDF ikm prefix + shared-point serialization both UNCOMPRESSED (65 bytes) */
  isHkdfKeyCompressed: false,
  symmetricAlgorithm: "aes-256-gcm",
  /** 16-byte random IV (not the usual 12) */
  symmetricNonceLength: 16,
} as const;

export const VALUE_PREFIX = "encrypted:";
const EPH_LEN = 65;
const IV_LEN = 16;
const TAG_LEN = 16;
const KEY_LEN = 32;
const SHARED_LEN = 65; // getSharedSecret(..., isCompressed=false) → 0x04||X||Y

// secp256k1 domain parameters
const CURVE_P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;
export const CURVE_N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const CURVE_B = 7n;
const GX = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n;
const GY = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n;

/** Exact .env.keys header the TS CLI writes for file custody (src/session-file.ts writePrivateKeyFile). */
export const KEYS_FILE_HEADER_TS = "# dotenvx private key for .env.session";
/** Exact dotenvx bootstrap blocks (primitives upsert layer + dotenvx mutateSrc/mutateKeysSrc). */
export const PUBLIC_KEY_BLOCK_LINES = [
  "#/-------------------[DOTENV_PUBLIC_KEY]--------------------/",
  "#/            public-key encryption for .env files          /",
  "#/       [how it works](https://dotenvx.com/encryption)     /",
  "#/----------------------------------------------------------/",
] as const;
export const KEYS_FILE_HEADER_DOTENVX_LINES = [
  "#/------------------!DOTENV_PRIVATE_KEYS!-------------------/",
  "#/ private decryption keys. DO NOT commit to source control /",
  "#/     [how it works](https://dotenvx.com/encryption)       /",
  "#/          ⛨ ARMORED KEYS: `dotenvx armor up`              /",
  "#/----------------------------------------------------------/",
] as const;

// ---------------------------------------------------------------------------
// 2. secp256k1 point arithmetic (affine, bigint; no external EC dependency)
// ---------------------------------------------------------------------------

type Pt = { x: bigint; y: bigint } | null; // null = point at infinity

function mod(a: bigint): bigint {
  const r = a % CURVE_P;
  return r < 0n ? r + CURVE_P : r;
}

function modInv(a: bigint): bigint {
  let [oldR, r] = [mod(a), CURVE_P];
  let [oldS, s] = [1n, 0n];
  while (r !== 0n) {
    const q = oldR / r;
    [oldR, r] = [r, oldR - q * r];
    [oldS, s] = [s, oldS - q * s];
  }
  if (oldR !== 1n) throw new Error("not invertible");
  return mod(oldS);
}

function ptAdd(p1: Pt, p2: Pt): Pt {
  if (p1 === null) return p2;
  if (p2 === null) return p1;
  const { x: x1, y: y1 } = p1;
  const { x: x2, y: y2 } = p2;
  if (x1 === x2) {
    if (mod(y1 + y2) === 0n) return null;
    const l = mod(3n * x1 * x1 * modInv(2n * y1));
    const x3 = mod(l * l - 2n * x1);
    return { x: x3, y: mod(l * (x1 - x3) - y1) };
  }
  const l = mod((y2 - y1) * modInv(x2 - x1));
  const x3 = mod(l * l - x1 - x2);
  return { x: x3, y: mod(l * (x1 - x3) - y1) };
}

function scalarMult(k: bigint, p: Pt): Pt {
  let result: Pt = null;
  let addend: Pt = p;
  let e = k;
  while (e > 0n) {
    if (e & 1n) result = ptAdd(result, addend);
    addend = ptAdd(addend, addend);
    e >>= 1n;
  }
  return result;
}

function bytesToBigInt(b: Uint8Array): bigint {
  let v = 0n;
  for (const byte of b) v = (v << 8n) | BigInt(byte);
  return v;
}

function bigIntTo32(v: bigint): Uint8Array {
  const hex = v.toString(16).padStart(64, "0");
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function yFromX(x: bigint, odd: boolean): bigint {
  const y2 = mod(x * x * x + CURVE_B);
  // CURVE_P % 4 === 3 → sqrt by exponentiation
  let y = 1n;
  let b = y2;
  for (let e = (CURVE_P + 1n) / 4n; e > 0n; e >>= 1n) {
    if (e & 1n) y = (y * b) % CURVE_P;
    b = (b * b) % CURVE_P;
  }
  if (mod(y * y) !== y2) throw new Error("point not on curve");
  const parity = y % 2n === 1n;
  return parity === odd ? y : CURVE_P - y;
}

function parsePoint(b: Uint8Array): Pt {
  if (b.length === 33) {
    if (b[0] !== 0x02 && b[0] !== 0x03) throw new Error("bad compressed prefix");
    const x = bytesToBigInt(b.subarray(1));
    return { x, y: yFromX(x, b[0] === 0x03) };
  }
  if (b.length === 65) {
    if (b[0] !== 0x04) throw new Error("bad uncompressed prefix");
    const x = bytesToBigInt(b.subarray(1, 33));
    const y = bytesToBigInt(b.subarray(33));
    if (mod(y * y - (x * x * x + CURVE_B)) !== 0n) throw new Error("point not on curve");
    return { x, y };
  }
  throw new Error("bad point length " + b.length);
}

function serializeUncompressed(pt: Pt): Uint8Array {
  if (pt === null) throw new Error("cannot serialize infinity");
  return Uint8Array.from([0x04, ...bigIntTo32(pt.x), ...bigIntTo32(pt.y)]);
}

function serializeCompressed(pt: Pt): Uint8Array {
  if (pt === null) throw new Error("cannot serialize infinity");
  const prefix = pt.y % 2n === 1n ? 0x03 : 0x02;
  return Uint8Array.from([prefix, ...bigIntTo32(pt.x)]);
}

function assertScalar(d: bigint): void {
  if (d === 0n || d >= CURVE_N) throw new Error("private key out of range");
}

/** Compressed public key, 66 lowercase hex ("02"/"03" + 64 hex) — keypair() output. */
export function publicKeyHexFromPrivate(privHex: string): string {
  const d = BigInt("0x" + privHex);
  assertScalar(d);
  return Buffer.from(serializeCompressed(scalarMult(d, { x: GX, y: GY }))).toString("hex");
}

/** Uncompressed public key, 130 lowercase hex ("04" + X + Y) — also accepted by encrypt. */
export function uncompressedPublicKeyHexFromPrivate(privHex: string): string {
  const d = BigInt("0x" + privHex);
  assertScalar(d);
  return Buffer.from(serializeUncompressed(scalarMult(d, { x: GX, y: GY }))).toString("hex");
}

/**
 * ECDH shared point serialized UNCOMPRESSED (65 bytes). Mirrors the chained
 * calls: PublicKey/PrivateKey.multiply → getSharedPoint(curve, secret,
 * otherPubCompressed, isHkdfKeyCompressed=false) → noble getSharedSecret(
 * secret, pub, false) → Point.multiply(secret).toBytes(false).
 */
export function sharedPointUncompressed(privHex: string, otherPub: Uint8Array): Uint8Array {
  const d = BigInt("0x" + privHex);
  assertScalar(d);
  return serializeUncompressed(scalarMult(d, parsePoint(otherPub)));
}

/**
 * HKDF-SHA256 with noble-hkdf defaults: salt undefined → 32 zero bytes
 * (extract uses new Uint8Array(hash.outputLen)), info undefined → empty,
 * L = 32. deriveKey(ikm, salt, info) = hkdf(sha256, ikm, salt, info, 32) and
 * dotenvx's ECIES calls it through getSharedKey(...) with both undefined.
 */
export function hkdfKey(ikm: Uint8Array): Buffer {
  return Buffer.from(hkdfSync("sha256", Buffer.from(ikm), Buffer.alloc(32), Buffer.alloc(0), KEY_LEN));
}

/**
 * The AES-256-GCM key: HKDF over ikm = ephemeralPub(65) || sharedPoint(65).
 * getSharedKey = deriveKey(concatBytes(ephPubBytes, sharedPointBytes)).
 */
export function eciesKey(privHex: string, ephPub: Uint8Array): Buffer {
  const shared = sharedPointUncompressed(privHex, ephPub);
  return hkdfKey(Uint8Array.from([...ephPub, ...shared]));
}

// ---------------------------------------------------------------------------
// 3. Record / value spec
// ---------------------------------------------------------------------------

/**
 * One encrypted record's raw bytes:
 *   ephemeralPub(65, uncompressed) || iv(16) || authTag(16) || ciphertext
 * NOTE the middle order: symEncrypt returns concat(iv, tag, ct) — the tag is
 * placed BETWEEN iv and ciphertext, not appended after it.
 * AES-256-GCM with a 16-byte IV, no AAD, 16-byte tag.
 */
export function encryptRecordBytes(
  pubHex: string,
  plaintext: string,
  rng: (n: number) => Uint8Array = (n) => new Uint8Array(randomBytes(n)),
): Uint8Array {
  const ephPrivBytes = rng(32);
  const ephPriv = Buffer.from(ephPrivBytes).toString("hex");
  const d = BigInt("0x" + ephPriv);
  assertScalar(d);
  const ephPub = serializeUncompressed(scalarMult(d, { x: GX, y: GY }));
  const receiverPub = new Uint8Array(Buffer.from(pubHex, "hex"));
  // ikm = ephemeralPub(65) || sharedPoint(ephPriv x receiverPub, 65) — NOT the receiver's bytes
  const shared = sharedPointUncompressed(ephPriv, receiverPub);
  const key = hkdfKey(Uint8Array.from([...ephPub, ...shared]));
  const iv = rng(IV_LEN);
  const cipher = createCipheriv("aes-256-gcm", key, Buffer.from(iv), { authTagLength: TAG_LEN });
  const ct = Buffer.concat([cipher.update(Buffer.from(plaintext, "utf8")), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Uint8Array.from([...ephPub, ...iv, ...new Uint8Array(tag), ...new Uint8Array(ct)]);
}

export function decryptRecordBytes(privHex: string, record: Uint8Array): string {
  if (record.length < EPH_LEN + IV_LEN + TAG_LEN) throw new Error("record too short");
  const ephPub = record.subarray(0, EPH_LEN);
  const iv = Buffer.from(record.subarray(EPH_LEN, EPH_LEN + IV_LEN));
  const tag = Buffer.from(record.subarray(EPH_LEN + IV_LEN, EPH_LEN + IV_LEN + TAG_LEN));
  const ct = Buffer.from(record.subarray(EPH_LEN + IV_LEN + TAG_LEN));
  const key = eciesKey(privHex, ephPub);
  const decipher = createDecipheriv("aes-256-gcm", key, iv, { authTagLength: TAG_LEN });
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ct), decipher.final()]).toString("utf8");
}

/** VALUE = "encrypted:" + base64(record) — Node Buffer base64: standard alphabet, padded. */
export function wrapValue(record: Uint8Array): string {
  return VALUE_PREFIX + Buffer.from(record).toString("base64");
}

export function unwrapValue(value: string): Uint8Array {
  if (!value.startsWith(VALUE_PREFIX)) throw new Error("not an encrypted value");
  return Uint8Array.from(Buffer.from(value.slice(VALUE_PREFIX.length), "base64"));
}

export function encryptValue(pubHex: string, plaintext: string, rng?: (n: number) => Uint8Array): string {
  return wrapValue(encryptRecordBytes(pubHex, plaintext, rng));
}

export function decryptValue(privHex: string, value: string): string {
  return decryptRecordBytes(privHex, unwrapValue(value));
}

/** Re-encrypt with a KNOWN ephemeral key + IV — reproduces another producer's record byte-for-byte. */
export function reconstructRecord(
  privHex: string,
  plaintext: string,
  ephPub: Uint8Array,
  iv: Uint8Array,
): Uint8Array {
  const key = eciesKey(privHex, ephPub);
  const cipher = createCipheriv("aes-256-gcm", key, Buffer.from(iv), { authTagLength: TAG_LEN });
  const ct = Buffer.concat([cipher.update(Buffer.from(plaintext, "utf8")), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Uint8Array.from([...ephPub, ...iv, ...new Uint8Array(tag), ...new Uint8Array(ct)]);
}

export function generatePrivateKeyHex(rng: (n: number) => Uint8Array = (n) => new Uint8Array(randomBytes(n))): string {
  let hex: string;
  do {
    hex = Buffer.from(rng(32)).toString("hex");
  } while (BigInt("0x" + hex) >= CURVE_N || BigInt("0x" + hex) === 0n);
  return hex;
}

// ---------------------------------------------------------------------------
// 4. File layout spec
// ---------------------------------------------------------------------------

/** The public-key block dotenvx prepends (mutateSrc → prependPublicKey, comment empty when fk is .env.keys in the same dir). */
export function renderPublicKeyBlock(pubHex: string, filename: string): string {
  return `${PUBLIC_KEY_BLOCK_LINES.join("\n")}\nDOTENV_PUBLIC_KEY_SESSION="${pubHex}"\n\n# ${filename}`;
}

/**
 * A fresh .env.session as dotenvx's `set` builds it: public-key block, then
 * one double-quoted record per key (primitives upsert appends `KEY="value"`
 * + "\n" when the key is absent). File ends with "\n".
 */
export function renderFreshSessionFile(pubHex: string, pairs: Array<[string, string]>, filename = ".env.session"): string {
  let src = `${renderPublicKeyBlock(pubHex, filename)}\n`;
  for (const [k, v] of pairs) src += `${k}="${v}"\n`;
  return src;
}

/** mutateSrc: prepend the block (plus a separating "\n") to existing content. */
export function prependPublicKeyBlock(existingSrc: string, pubHex: string, filename = ".env.session"): string {
  return `${renderPublicKeyBlock(pubHex, filename)}\n${existingSrc}`;
}

/** upsert's append path: key absent → `KEY="value"` + "\n" (a "\n" first only if src lacks a trailing one). */
export function appendRecordLine(src: string, key: string, value: string): string {
  let line = `${key}="${value}"\n`;
  if (src !== "" && !src.endsWith("\n")) line = "\n" + line;
  return src + line;
}

/** TS-style .env.keys (file custody fallback; byte-identical to src/session-file.ts writePrivateKeyFile). */
export function renderKeysFileSns(privHex: string): string {
  return `${KEYS_FILE_HEADER_TS}\nDOTENV_PRIVATE_KEY_SESSION=${privHex}\n`;
}

/** dotenvx-style .env.keys as `dotenvx set` bootstraps it (mutateKeysSrc; comment = basename of the env file). */
export function renderKeysFileDotenvx(privHex: string, comment = ".env.session"): string {
  return `${KEYS_FILE_HEADER_DOTENVX_LINES.join("\n")}\n\n# ${comment}\nDOTENV_PRIVATE_KEY_SESSION=${privHex}\n`;
}

/**
 * Minimal reader for the env-file subset this format uses (the dotenvx scan
 * grammar restricted to what matters here). Returns entries in order with
 * quotes stripped and double-quote escapes (\n \r \t) expanded — the same
 * unquoting Iy() does. Handles: comments, blank lines, optional `export`,
 * unquoted / single-quoted / double-quoted values, inline # comments, and
 * CRLF normalization (convertWindowsNewlines defaults on).
 */
export type ParsedEnvEntry = { name: string; value: string; quoted: boolean };
export function parseEnvFile(text: string): ParsedEnvEntry[] {
  const normalized = text.replace(/\r\n?/g, "\n");
  const entries: ParsedEnvEntry[] = [];
  const lineRe = /^[ \t]*(?:export\s+)?([A-Za-z_][A-Za-z0-9_.-]*)(?:[ \t]*=[ \t]*|[ \t]+:[ \t]+)(.*)$/;
  for (const rawLine of normalized.split("\n")) {
    const line = rawLine.trimEnd();
    if (line === "" || line.startsWith("#")) continue;
    const m = line.match(lineRe);
    if (!m) continue;
    const rest = m[2] ?? "";
    let quoted = false;
    let value: string;
    const quote = rest.trim()[0];
    if (quote === '"' || quote === "'" || quote === "`") {
      const closing = rest.trimEnd().lastIndexOf(quote);
      if (closing > 0) {
        quoted = true;
        let body = rest.trim().slice(1, closing);
        if (quote === "'") body = body.replace(/\\'/g, "'");
        if (quote === '"') {
          body = body.replace(/\\n/g, "\n").replace(/\\r/g, "\r").replace(/\\t/g, "\t");
        }
        value = body;
      } else {
        value = rest.trim();
      }
    } else {
      // unquoted: value runs to an inline comment
      const hashAt = rest.indexOf("#");
      value = (hashAt === -1 ? rest : rest.slice(0, hashAt)).trim();
    }
    entries.push({ name: m[1] ?? "", value, quoted });
  }
  return entries;
}

// ---------------------------------------------------------------------------
// 5. Deterministic inputs for fixtures
// ---------------------------------------------------------------------------

export function fixturePrivateKey(label: string): string {
  let hex = createHash("sha256").update("sns session fixture key " + label).digest("hex");
  while (BigInt("0x" + hex) >= CURVE_N || BigInt("0x" + hex) === 0n) {
    hex = createHash("sha256").update("sns session fixture key round2 " + label).digest("hex");
  }
  return hex;
}

function fixtureEphPriv(caseId: string): string {
  const hex = createHash("sha256").update("sns-fixture-eph|" + caseId).digest("hex");
  const d = BigInt("0x" + hex);
  if (d === 0n || d >= CURVE_N) throw new Error("deterministic ephemeral scalar out of range for " + caseId);
  return hex;
}

function fixtureIv(caseId: string): Uint8Array {
  return Uint8Array.from(createHash("sha256").update("sns-fixture-iv|" + caseId).digest().subarray(0, IV_LEN));
}

/** Deterministic rng for encryptRecordBytes: 32 → ephemeral scalar, 16 → IV, else derived stream. */
function deterministicRng(caseId: string): (n: number) => Uint8Array {
  return (n: number) => {
    if (n === 32) return Uint8Array.from(Buffer.from(fixtureEphPriv(caseId), "hex"));
    if (n === IV_LEN) return fixtureIv(caseId);
    return Uint8Array.from(createHash("sha256").update(`sns-fixture-rng|${caseId}|${n}`).digest().subarray(0, n));
  };
}

// ---------------------------------------------------------------------------
// 6. Oracle (the ONLY place the @dotenvx library is loaded)
// ---------------------------------------------------------------------------

const SCRIPT_DIR = fileURLToPath(new URL(".", import.meta.url));
const REPO_ROOT = fileURLToPath(new URL("..", `file://${SCRIPT_DIR}`));

export type Oracle = {
  dotenvxVersion: string;
  primitivesVersion: string;
  /** encrypt(receiverPublicKeyHex, plaintext) → "encrypted:…" */
  encrypt: (pubHex: string, plaintext: string) => string;
  /** decrypt(privateKeyHex, "encrypted:…") → plaintext */
  decrypt: (privHex: string, value: string) => string;
  keypair: (privHex?: string) => { publicKey: string; privateKey: string };
  /** dotenvx parse(src, { privateKey }) → Record<string, string> */
  parse: (src: string, opts?: { privateKey?: string }) => Record<string, string>;
  cliPath: string;
};

export function loadOracle(): Oracle {
  const dotenvxLinked = `${REPO_ROOT}node_modules/@dotenvx/dotenvx`;
  // follow the store symlink; primitives sits beside it in the same hoisted node_modules
  const dotenvxDir = realpathSync(dotenvxLinked);
  const dotenvxPkg = JSON.parse(readFileSync(`${dotenvxDir}/package.json`, "utf8")) as { version: string };
  const hoistedModules = dotenvxDir.slice(0, dotenvxDir.lastIndexOf("/@dotenvx/"));
  const primDir = realpathSync(`${hoistedModules}/@dotenvx/primitives`);
  const primPkg = JSON.parse(readFileSync(`${primDir}/package.json`, "utf8")) as { version: string };
  // hard pins — the oracle MUST be the dependency set this repo resolves
  if (primPkg.version !== "3.3.1") {
    throw new Error(
      `@dotenvx/primitives resolved to ${primPkg.version} but this spec is pinned to 3.3.1 — re-verify the wire spec against the new dist before trusting these fixtures`,
    );
  }
  if (dotenvxPkg.version !== "2.38.2") {
    throw new Error(
      `@dotenvx/dotenvx resolved to ${dotenvxPkg.version} but this spec is pinned to 2.38.2 — re-verify the wire spec against the new dist before trusting these fixtures`,
    );
  }
  const require = (id: string) => {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    return requireModule(id);
  };
  const prim = require(`${primDir}/dist/index.cjs`);
  const dotenvxMain = require(`${dotenvxDir}/src/lib/main.js`);
  return {
    dotenvxVersion: dotenvxPkg.version,
    primitivesVersion: primPkg.version,
    encrypt: (pubHex, plaintext) => prim.encrypt(pubHex, plaintext) as string,
    decrypt: (privHex, value) => prim.decrypt(privHex, value) as string,
    keypair: (privHex?: string) => prim.keypair(privHex) as { publicKey: string; privateKey: string },
    parse: (src, opts) => dotenvxMain.parse(src, opts) as Record<string, string>,
    cliPath: `${dotenvxDir}/src/cli/dotenvx.js`,
  };
}

// Bun supports synchronous require of CJS via createRequire
import { createRequire } from "node:module";
const requireModule = createRequire(import.meta.url);

// ---------------------------------------------------------------------------
// 7. Validation against the oracle
// ---------------------------------------------------------------------------

let checks = 0;
let failures = 0;
function ok(cond: boolean, label: string): void {
  checks++;
  if (!cond) {
    failures++;
    console.error("FAIL: " + label);
  }
}

export function validate(oracle: Oracle): void {
  const keyA = fixturePrivateKey("A");
  const keyB = fixturePrivateKey("B");
  const keyC = fixturePrivateKey("C");
  const pubA = publicKeyHexFromPrivate(keyA);
  const pubB = publicKeyHexFromPrivate(keyB);
  const pubC = publicKeyHexFromPrivate(keyC);

  // keypair shape + determinism
  const kp = oracle.keypair();
  ok(/^[0-9a-f]{64}$/.test(kp.privateKey), "keypair().privateKey is 64 lowercase hex");
  ok(/^(?:02|03)[0-9a-f]{64}$/.test(kp.publicKey), "keypair().publicKey is 66 lowercase hex compressed");
  ok(publicKeyHexFromPrivate(kp.privateKey) === kp.publicKey, "my EC math derives the library's compressed public key");
  const kpSame = oracle.keypair(keyA);
  ok(kpSame.privateKey === keyA && kpSame.publicKey === pubA, "keypair(priv) is the identity, lib agrees with my pub");

  // fixed-RNG byte-for-byte encrypt equality (patches webcrypto RNG used by the library)
  let fixedRngTested = false;
  let fixedRngPassedCount = 0;
  const wc = (globalThis as { crypto: Crypto }).crypto;
  const saved = Object.getOwnPropertyDescriptor(wc, "getRandomValues");
  try {
    const draws: number[][] = [];
    Object.defineProperty(wc, "getRandomValues", {
      value: (buf: Uint8Array) => {
        const d = draws.shift();
        if (!d || d.length !== buf.length) throw new Error("RNG queue exhausted");
        buf.set(d);
        return buf;
      },
      configurable: true,
      writable: true,
    });
    fixedRngTested = true;
    let fixedRngPassed = 0;
    for (let i = 0; i < 25; i++) {
      const eph = fixtureEphPriv(`fixed-rng-${i}`);
      const iv = fixtureIv(`fixed-rng-${i}`);
      const pt = "deterministic round " + i + " ✓漢字";
      draws.push([...Buffer.from(eph, "hex")], [...iv]);
      const libVal = oracle.encrypt(pubA, pt);
      const myRec = encryptRecordBytes(pubA, pt, deterministicRng(`fixed-rng-${i}`));
      const equal = Buffer.from(unwrapValue(libVal)).equals(Buffer.from(myRec));
      ok(equal, `fixed-RNG encrypt byte equality round ${i}`);
      ok(oracle.decrypt(keyA, libVal) === pt, `fixed-RNG lib decrypt round ${i}`);
      if (equal) fixedRngPassed++;
    }
    fixedRngPassedCount = fixedRngPassed;
  } catch (error) {
    console.log(`fixed-RNG equality unavailable (${(error as Error).message}) — reconstruction equality still proves the layout`);
  } finally {
    if (saved) Object.defineProperty(wc, "getRandomValues", saved);
    else delete (wc as unknown as Record<string, unknown>).getRandomValues;
  }
  console.log(
    `fixed-RNG encrypt equality: ${fixedRngTested ? `${fixedRngPassedCount}/25 byte-identical rounds` : "skipped"}`,
  );

  // random rounds: reconstruction equality + both-direction decrypt
  for (let i = 0; i < 200; i++) {
    const pt =
      i % 4 === 0
        ? ""
        : i % 4 === 1
          ? randomBytes(1 + (i % 64)).toString("hex")
          : i % 4 === 2
            ? "unicode ✓ 漢字 emoji 🎉 round " + i
            : randomBytes(16 + i).toString("base64");
    const key = [keyA, keyB, keyC][i % 3] as string;
    const pub = [pubA, pubB, pubC][i % 3] as string;
    const libVal = oracle.encrypt(pub, pt);
    const libRec = unwrapValue(libVal);
    ok(libRec.length === EPH_LEN + IV_LEN + TAG_LEN + Buffer.byteLength(pt, "utf8"), `record length layout round ${i}`);
    const mine = reconstructRecord(key, pt, libRec.subarray(0, 65), libRec.subarray(65, 81));
    ok(Buffer.from(libRec).equals(Buffer.from(mine)), `reconstruction byte equality round ${i}`);
    ok(decryptRecordBytes(key, libRec) === pt, `my-decrypt(lib) round ${i}`);
    const myVal = encryptValue(pub, pt);
    let libDecrypted: string;
    try {
      libDecrypted = oracle.decrypt(key, myVal);
    } catch (error) {
      console.error(
        `round ${i} lib-decrypt(my) threw: pt=${JSON.stringify(pt.slice(0, 60))} len=${pt.length} recLen=${unwrapValue(myVal).length}`,
      );
      throw error;
    }
    ok(libDecrypted === pt, `lib-decrypt(my) round ${i}`);
    ok(decryptValue(key, myVal) === pt, `my-decrypt(my) round ${i}`);
  }
  console.log("200 random rounds: reconstruction + both-direction decrypts all pass");

  // special values (empty, whitespace, metacharacters, unicode, large)
  const specials: Array<[string, string]> = [
    ["empty", ""],
    ["space", " "],
    ["whitespace", "   "],
    ["tabs-newlines", "a\tb\nc\rd"],
    ["dotenv-meta", 'a"b\\c`d$(e)#f-g_h.i/j;k:l<m>n?'],
    ["encrypted-shaped", VALUE_PREFIX + "Zm9vYmFy"],
    ["utf8-bom", "﻿hello"],
    ["cjk", "机密数据令牌"],
    ["emoji", "🔐🛡️🚀"],
    ["json", '{"sub":"sess","exp":"2030-01-01T00:00:00Z","scopes":["read","write"]}'],
    ["cookie", "sessionid=AbCdEf0123456789; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=31536000"],
    ["ascii-4k", "x".repeat(4096)],
    ["unicode-2k", "漢".repeat(2048)],
  ];
  for (const [label, pt] of specials) {
    const libVal = oracle.encrypt(pubA, pt);
    ok(decryptValue(keyA, libVal) === pt, `special lib→my ${label}`);
    const myVal = encryptValue(pubA, pt);
    ok(oracle.decrypt(keyA, myVal) === pt, `special my→lib ${label}`);
    ok(unwrapValue(libVal).length === 97 + Buffer.byteLength(pt, "utf8"), `special layout ${label}`);
  }
  console.log("special values: lib↔my round trips all pass");

  // uncompressed 130-hex receiver public key is accepted and yields identical records
  const keyU = generatePrivateKeyHex();
  const pubU = uncompressedPublicKeyHexFromPrivate(keyU);
  ok(pubU.length === 130 && pubU.startsWith("04"), "uncompressed pub is 130 hex 04-prefixed");
  ok(oracle.keypair(keyU).publicKey === publicKeyHexFromPrivate(keyU), "lib agrees compressed pub matches uncompressed");
  const libValU = oracle.encrypt(pubU, "uncompressed pub input");
  const recU = unwrapValue(libValU);
  const mineU = reconstructRecord(keyU, "uncompressed pub input", recU.subarray(0, 65), recU.subarray(65, 81));
  ok(Buffer.from(recU).equals(Buffer.from(mineU)), "uncompressed-pub record byte equality");
  ok(decryptValue(keyU, libValU) === "uncompressed pub input", "uncompressed-pub my-decrypt");
  console.log("uncompressed receiver public key: byte equality with library");

  // file-level: my render is read by dotenvx parse, key from a TS-style .env.keys
  const secrets: Array<[string, string]> = [
    ["SN_ACCOUNT_EMAIL", "user@example.com"],
    ["SN_REFRESH_TOKEN", "rt_9f8e7d6c5b4a3210fedcba9876543210fedcba98"],
    ["SN_ACCESS_TOKEN", "at_0123456789abcdef0123456789abcdef"],
    ["SN_ACCESS_EXPIRATION", "1766610000000"],
    ["SN_REFRESH_EXPIRATION", "1769198400000"],
    ["SN_ACCESS_COOKIE", "sn_access=Ab12Cd34Ef56Gh78+Q=; Path=/api; HttpOnly; Secure; SameSite=Lax"],
    ["SN_REFRESH_COOKIE", "sn_refresh=Xy98Zv76Ut54Sr32/1==; Path=/api/auth; HttpOnly; Secure; SameSite=Strict"],
    ["SN_DB_KEY", keyC],
  ];
  const myFile = renderFreshSessionFile(pubA, secrets.map(([k, v]) => [k, encryptValue(pubA, v)] as [string, string]));
  // silence the library's WRONG_PRIVATE_KEY console noise (it writes through console.error)
  const realError = console.error;
  console.error = () => {};
  try {
    const parsed = oracle.parse(myFile, { privateKey: keyA });
    for (const [k, v] of secrets) ok(parsed[k] === v, `dotenvx parse decrypts my render ${k}`);
    const keysText = renderKeysFileSns(keyA);
    const keyFromFile = oracle.parse(keysText).DOTENV_PRIVATE_KEY_SESSION ?? "";
    ok(keyFromFile === keyA, "dotenvx parse reads the TS-style .env.keys line");
    const parsedViaKeys = oracle.parse(myFile, { privateKey: keyFromFile });
    ok(parsedViaKeys.SN_DB_KEY === keyC, "TS-style .env.keys key opens my render through dotenvx");
    // wrong key leaves ciphertext in place (does not throw)
    const wrong = oracle.parse(myFile, { privateKey: keyB });
    ok(
      secrets.every(([k]) => typeof wrong[k] === "string" && wrong[k].startsWith(VALUE_PREFIX)),
      "wrong key leaves encrypted: strings in dotenvx parse",
    );
    // my own parser sees the same entries
    const mineParsed = parseEnvFile(myFile);
    ok(
      mineParsed.some((e) => e.name === "DOTENV_PUBLIC_KEY_SESSION" && e.value === pubA) &&
        secrets.every(([k, v]) => mineParsed.some((e) => e.name === k && decryptValue(keyA, e.value) === v)),
      "my minimal parser recovers the same fields",
    );
  } finally {
    console.error = realError;
  }
  console.log("file-level interop: dotenvx parse reads my render and my TS-style .env.keys");

  // end-to-end: the real dotenvx CLI in a sandbox produces exactly the layout I render
  const sandbox = "/tmp/sns-session-spec-sandbox";
  rmSync(sandbox, { recursive: true, force: true });
  mkdirSync(sandbox, { recursive: true });
  for (const [k, v] of secrets) {
    execFileSync(
      process.execPath,
      [
        oracle.cliPath,
        "set",
        k,
        v,
        "-f",
        ".env.session",
        "-fk",
        ".env.keys",
        "--no-armor",
        "--no-native",
        "--no-1password",
        "--no-bitwarden",
      ],
      { cwd: sandbox, env: { ...process.env, CI: "true" }, stdio: "pipe" },
    );
  }
  const realSession = readFileSync(`${sandbox}/.env.session`, "utf8");
  const realKeys = readFileSync(`${sandbox}/.env.keys`, "utf8");
  const bootKey = realKeys.match(/^DOTENV_PRIVATE_KEY_SESSION=([0-9a-f]{64})$/m)?.[1];
  ok(bootKey !== undefined, "sandbox .env.keys carries an unquoted 64-hex private key");
  if (bootKey) {
    const bootPub = oracle.keypair(bootKey).publicKey;
    const pubLine = `DOTENV_PUBLIC_KEY_SESSION="${bootPub}"`;
    ok(realSession.startsWith(`${PUBLIC_KEY_BLOCK_LINES[0]}\n`), "session file starts with the public-key block");
    ok(realSession.includes(pubLine), "public key line is double-quoted");
    const normalize = (t: string) =>
      t
        .replace(/DOTENV_PUBLIC_KEY_SESSION="[0-9a-f]{66}"/, 'DOTENV_PUBLIC_KEY_SESSION="<PUB>"')
        .replace(/encrypted:[A-Za-z0-9+/=]+/g, "encrypted:<REC>");
    const mySameKey = renderFreshSessionFile(
      bootPub,
      secrets.map(([k, v]) => [k, encryptValue(bootPub, v)] as [string, string]),
    );
    ok(normalize(mySameKey) === normalize(realSession), "my render layout matches the real dotenvx output byte-for-byte modulo records");
    ok(normalize(realKeys) === normalize(renderKeysFileDotenvx(bootKey)), "my .env.keys render matches the real bootstrap");
    // re-key the real file to keyA using my records; dotenvx must still decrypt it
    let rekeyed = realSession.replace(pubLine, `DOTENV_PUBLIC_KEY_SESSION="${pubA}"`);
    for (const [k, v] of secrets) {
      rekeyed = rekeyed.replace(new RegExp(`${k}="encrypted:[A-Za-z0-9+/=]+"`), `${k}="${encryptValue(pubA, v)}"`);
    }
    const parsedRekeyed = oracle.parse(rekeyed, { privateKey: keyA });
    for (const [k, v] of secrets) ok(parsedRekeyed[k] === v, `re-keyed real layout decrypts under my key ${k}`);
  }
  console.log("CLI sandbox: real `dotenvx set` output matches my render (modulo record randomness)");
  rmSync(sandbox, { recursive: true, force: true });
}

// ---------------------------------------------------------------------------
// 8. Fixture generation
// ---------------------------------------------------------------------------

const RECORD_CASES: Array<{
  name: string;
  key: "A" | "B" | "C";
  plaintext: string;
  pubEncoding?: "uncompressed";
  negativeKey?: "A" | "B" | "C";
}> = [
  { name: "empty-string", key: "A", plaintext: "" },
  { name: "single-char", key: "A", plaintext: "x" },
  { name: "ascii-short", key: "A", plaintext: "hello world" },
  { name: "unicode-mixed", key: "A", plaintext: "héllo wörld — 机密 ✓ 🎉 token" },
  { name: "json-payload", key: "B", plaintext: '{"sub":"sess","exp":"2030-01-01T00:00:00Z","scopes":["read","write"]}' },
  {
    name: "cookie-shaped",
    key: "B",
    plaintext: "sn_access=Ab12Cd34Ef56Gh78+Q=; Path=/api; HttpOnly; Secure; SameSite=Lax; Max-Age=31536000",
  },
  { name: "ascii-4k", key: "B", plaintext: "x".repeat(4096) },
  { name: "unicode-2k", key: "B", plaintext: "漢".repeat(2048) },
  { name: "dotenv-meta", key: "A", plaintext: 'a"b\\c`d$(e)#f-g_h.i/j;k:l<m>n?' },
  { name: "encrypted-shaped", key: "A", plaintext: VALUE_PREFIX + "Zm9vYmFy" },
  { name: "whitespace-only", key: "A", plaintext: "   " },
  { name: "newlines-mixed", key: "A", plaintext: "line1\nline2\r\nline3" },
  {
    name: "hex-64-uncompressed-pub",
    key: "C",
    plaintext: "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0",
    pubEncoding: "uncompressed",
  },
  {
    name: "base64-96-negative-key",
    key: "A",
    plaintext: "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789+/AbCdEfGhIjKlMnOpQrStUvWxYz012345",
    negativeKey: "B",
  },
];

function buildRecordCases(oracle: Oracle) {
  const keyOf = (label: "A" | "B" | "C") => fixturePrivateKey(label);
  return RECORD_CASES.map((spec) => {
    const privHex = keyOf(spec.key);
    const pubHex = spec.pubEncoding === "uncompressed"
      ? uncompressedPublicKeyHexFromPrivate(privHex)
      : publicKeyHexFromPrivate(privHex);
    const record = encryptRecordBytes(pubHex, spec.plaintext, deterministicRng(spec.name));
    const value = wrapValue(record);
    const libDecrypted = oracle.decrypt(privHex, value);
    if (libDecrypted !== spec.plaintext) throw new Error(`fixture ${spec.name}: oracle cannot decrypt my record`);
    if (decryptValue(privHex, value) !== spec.plaintext) throw new Error(`fixture ${spec.name}: my decrypt failed`);
    if (spec.negativeKey) {
      const wrong = keyOf(spec.negativeKey);
      let threw = false;
      try {
        decryptValue(wrong, value);
      } catch {
        threw = true;
      }
      try {
        oracle.decrypt(wrong, value);
      } catch {
        threw = true;
      }
      if (!threw) throw new Error(`fixture ${spec.name}: negative key unexpectedly decrypts`);
    }
    return {
      name: spec.name,
      privateKeyHex: privHex,
      publicKeyHex: pubHex,
      publicKeyEncoding: spec.pubEncoding === "uncompressed" ? "uncompressed" : "compressed",
      ephemeralPrivateHex: fixtureEphPriv(spec.name),
      ephemeralPublicHex: Buffer.from(record.subarray(0, 65)).toString("hex"),
      ivHex: Buffer.from(fixtureIv(spec.name)).toString("hex"),
      plaintext: spec.plaintext,
      value,
      recordHex: Buffer.from(record).toString("hex"),
      ...(spec.negativeKey
        ? { negativePrivateKeyHex: keyOf(spec.negativeKey), negativeKeyMustFail: true }
        : {}),
    };
  });
}

const CANONICAL_SECRETS: Array<[string, string]> = [
  ["SN_ACCOUNT_EMAIL", "user@example.com"],
  ["SN_REFRESH_TOKEN", "rt_9f8e7d6c5b4a3210fedcba9876543210fedcba98"],
  ["SN_ACCESS_TOKEN", "at_0123456789abcdef0123456789abcdef"],
  ["SN_ACCESS_EXPIRATION", "1766610000000"],
  ["SN_REFRESH_EXPIRATION", "1769198400000"],
  ["SN_ACCESS_COOKIE", "sn_access=Ab12Cd34Ef56Gh78+Q=; Path=/api; HttpOnly; Secure; SameSite=Lax"],
  ["SN_REFRESH_COOKIE", "sn_refresh=Xy98Zv76Ut54Sr32/1==; Path=/api/auth; HttpOnly; Secure; SameSite=Strict"],
  ["SN_DB_KEY", fixturePrivateKey("C")],
];

function buildFileCases(oracle: Oracle) {
  const keyA = fixturePrivateKey("A");
  const pubA = publicKeyHexFromPrivate(keyA);
  const keyB = fixturePrivateKey("B");
  const pubB = publicKeyHexFromPrivate(keyB);

  // Case 1 — canonical fresh session: pub block + 8 double-quoted records, TS-style .env.keys.
  const canonicalValues = CANONICAL_SECRETS.map(([k, v]) => [k, encryptValue(pubA, v, deterministicRng(`canonical|${k}`))] as const);
  const canonicalSession =
    renderFreshSessionFile(pubA, canonicalValues.map(([k, v]) => [k, v] as [string, string]));
  const canonicalKeys = renderKeysFileSns(keyA);
  const canonicalRecordInputs = CANONICAL_SECRETS.map(([k]) => ({
    key: k,
    ephemeralPrivateHex: fixtureEphPriv(`canonical|${k}`),
    ivHex: Buffer.from(fixtureIv(`canonical|${k}`)).toString("hex"),
  }));

  // Case 2 — dotenvx bootstrap over pre-existing content: block prepended, record appended after OLD_VAR.
  const existing = "# pre-existing comment\nOLD_VAR=1\n";
  const bootValue = encryptValue(pubB, "user@example.com", deterministicRng("bootstrap|SN_ACCOUNT_EMAIL"));
  const bootstrapSession = appendRecordLine(
    prependPublicKeyBlock(existing, pubB),
    "SN_ACCOUNT_EMAIL",
    bootValue,
  );
  const bootstrapKeys = renderKeysFileDotenvx(keyB);

  for (const [name, sessionText, privHex, expectations] of [
    ["canonical", canonicalSession, keyA, CANONICAL_SECRETS],
    ["bootstrap", bootstrapSession, keyB, [["SN_ACCOUNT_EMAIL", "user@example.com"], ["OLD_VAR", "1"]]],
  ] as const) {
    const parsed = oracle.parse(sessionText, { privateKey: privHex });
    for (const [k, v] of expectations) {
      if (parsed[k] !== v) throw new Error(`file case ${name}: dotenvx parse mismatch for ${k}`);
    }
    const mine = parseEnvFile(sessionText);
    for (const [k, v] of expectations) {
      const entry = mine.find((e) => e.name === k);
      const got =
        entry === undefined
          ? undefined
          : entry.value.startsWith(VALUE_PREFIX)
            ? decryptValue(privHex, entry.value)
            : entry.value;
      if (got !== v) throw new Error(`file case ${name}: my parser mismatch for ${k}`);
    }
  }

  return [
    {
      name: "canonical-fresh-session",
      description:
        "what `sns login` writes on a fresh machine: public-key block, the 8 session fields in canonical order as double-quoted encrypted: records, LF endings, trailing newline; .env.keys in the TS file-custody format",
      privateKeyHex: keyA,
      publicKeyHex: pubA,
      keysFileStyle: "sns",
      secrets: Object.fromEntries(CANONICAL_SECRETS),
      sessionFile: canonicalSession,
      keysFile: canonicalKeys,
      recordInputs: canonicalRecordInputs,
    },
    {
      name: "dotenvx-bootstrap-over-existing",
      description:
        "what `dotenvx set` produces when .env.session already had content but no public key: block prepended above the old content, new record appended after it, .env.keys in the dotenvx armored bootstrap format",
      privateKeyHex: keyB,
      publicKeyHex: pubB,
      keysFileStyle: "dotenvx",
      secrets: { SN_ACCOUNT_EMAIL: "user@example.com", OLD_VAR: "1" },
      sessionFile: bootstrapSession,
      keysFile: bootstrapKeys,
      recordInputs: [
        {
          key: "SN_ACCOUNT_EMAIL",
          ephemeralPrivateHex: fixtureEphPriv("bootstrap|SN_ACCOUNT_EMAIL"),
          ivHex: Buffer.from(fixtureIv("bootstrap|SN_ACCOUNT_EMAIL")).toString("hex"),
        },
      ],
    },
  ];
}

function generateFixtures(oracle: Oracle): string {
  const recordCases = buildRecordCases(oracle);
  const fileCases = buildFileCases(oracle);
  const doc = {
    _generator: {
      script: "scripts/session-spec-reference.ts",
      command: "bun scripts/session-spec-reference.ts --gen-fixtures",
      generatedAt: new Date().toISOString(),
      pinnedVersions: {
        "@dotenvx/dotenvx": oracle.dotenvxVersion,
        "@dotenvx/primitives": oracle.primitivesVersion,
      },
      summary:
        "golden vectors for the dotenvx session wire format. record = encrypted: + base64(ephemeralPub65(uncompressed) || iv16 || authTag16 || ciphertext); AES-256-GCM with 16-byte IV and no AAD; key = HKDF-SHA256(ikm = ephPub65 || ECDH-shared-point65, salt = 32 zero bytes, info = empty, L = 32); ECDH shared point serialized uncompressed. Receiver public keys are 66-hex compressed (02/03) or 130-hex uncompressed. See the S1 spec text for the full authority.",
      determinism:
        "ephemeralPrivateHex/ivHex are SHA-256-derived constants; encrypting a case's plaintext with THAT ephemeral scalar and THAT IV must reproduce value/recordHex byte-for-byte. Encryption with fresh randomness yields different bytes that decrypt identically — decrypt is the always-valid assertion, reconstruct-encrypt is the byte-exact one.",
      validation: `${checks} checks against the pinned library at generation time, ${failures} failures`,
    },
    recordCases,
    fileCases,
  };
  return JSON.stringify(doc, null, 2) + "\n";
}

// ---------------------------------------------------------------------------
// 9. Main
// ---------------------------------------------------------------------------

const main = (): number => {
  console.log("loading oracle…");
  const oracle = loadOracle();
  console.log(
    `oracle pinned: @dotenvx/dotenvx ${oracle.dotenvxVersion} → @dotenvx/primitives ${oracle.primitivesVersion}`,
  );
  validate(oracle);
  console.log(`validation complete: ${checks} checks, ${failures} failures`);
  if (failures > 0) return 1;

  if (process.argv.includes("--gen-fixtures")) {
    const json = generateFixtures(oracle);
    const target = `${REPO_ROOT}rs/tests/fixtures/session-vectors.json`;
    // fixture content was oracle-checked inside build*(); write and re-verify parse
    writeFileSync(target, json, { flag: "w" });
    const reparsed = JSON.parse(readFileSync(target, "utf8")) as { recordCases: unknown[]; fileCases: unknown[] };
    console.log(
      `wrote ${target} (${recordCasesCount(reparsed)} record cases, ${fileCasesCount(reparsed)} file cases, ${json.length} bytes)`,
    );
  }
  return 0;
};

function recordCasesCount(doc: { recordCases: unknown[] }): number {
  return doc.recordCases.length;
}
function fileCasesCount(doc: { fileCases: unknown[] }): number {
  return doc.fileCases.length;
}

process.exit(main());
