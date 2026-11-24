import { expect, test } from "bun:test";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parse } from "@dotenvx/dotenvx";
import { SESSION_VALUE_KEYS } from "./env.ts";
import { ensureConfigDir, keysPath, withConfigDir } from "./paths.ts";
import { readPrivateKeyFile } from "./session-file.ts";

// A test must never touch the developer's real keychain or config dir.
process.env.SNS_DISABLE_KEYCHAIN ??= "1";

/**
 * Golden vectors for the dotenvx session wire format — the same fixture the
 * Rust tests assert (`rs/src/session.rs`, `rs/tests/fixtures/session-vectors.json`).
 * The vectors were generated from the pinned @dotenvx/dotenvx 2.38.2 /
 * @dotenvx/primitives 3.3.1 library by `scripts/session-spec-reference.ts`,
 * so every assertion here pins the TS CLI's reader to the library's own
 * bytes: one `.env.session` serves the TypeScript CLI, the Rust CLI, and the
 * `dotenvx` CLI alike.
 */
type RecordCase = {
  name: string;
  privateKeyHex: string;
  publicKeyHex: string;
  publicKeyEncoding: string;
  ephemeralPrivateHex: string;
  ephemeralPublicHex: string;
  ivHex: string;
  plaintext: string;
  value: string;
  recordHex: string;
  negativePrivateKeyHex?: string;
  negativeKeyMustFail?: boolean;
};

type FileCase = {
  name: string;
  privateKeyHex: string;
  publicKeyHex: string;
  keysFileStyle: string;
  secrets: Record<string, string>;
  sessionFile: string;
  keysFile: string;
};

type Vectors = {
  recordCases: RecordCase[];
  fileCases: FileCase[];
};

const vectors: Vectors = JSON.parse(
  readFileSync(join(import.meta.dir, "../rs/tests/fixtures/session-vectors.json"), "utf8"),
);

/** A minimal session file carrying one record under one field name. */
function recordWrapper(publicKeyHex: string, field: string, record: string): string {
  return `DOTENV_PUBLIC_KEY_SESSION="${publicKeyHex}"\n\n# .env.session\n${field}="${record}"\n`;
}

/**
 * dotenvx logs one `☠ [WRONG/INVALID_PRIVATE_KEY] …` line per field when a
 * key does not match (echoing key-material prefixes), through console.error.
 * Intercepted exactly around one parse, mirroring `keyDecryptsSession`.
 */
function quietly<T>(fn: () => T): T {
  const write = process.stderr.write;
  const log = console.error;
  process.stderr.write = () => true;
  console.error = () => {};
  try {
    return fn();
  } finally {
    process.stderr.write = write;
    console.error = log;
  }
}

/**
 * True when no contract field still holds exactly its original record. A
 * wrong key leaves the ciphertext in place; a successful decrypt always
 * changes the value. The comparison is exact on purpose — one golden vector
 * ("encrypted-shaped") decrypts TO a string that itself starts with
 * `encrypted:`, so a prefix heuristic would misread success as failure.
 */
function noLeftoverCiphertext(parsed: Record<string, string>, records: Record<string, string>): boolean {
  return !SESSION_VALUE_KEYS.some((key) => records[key] !== undefined && parsed[key] === records[key]);
}

test("the pinned library decrypts every golden record case to its recorded plaintext", () => {
  expect(vectors.recordCases.length).toBe(14);
  for (const recordCase of vectors.recordCases) {
    const parsed = quietly(() =>
      parse(recordWrapper(recordCase.publicKeyHex, "SN_DB_KEY", recordCase.value), {
        privateKey: recordCase.privateKeyHex,
      }),
    );
    expect(parsed.SN_DB_KEY).toBe(recordCase.plaintext);
    // The header line lifts out with its quotes stripped — compressed 66-hex
    // and uncompressed 130-hex receiver encodings both accepted.
    expect(parsed.DOTENV_PUBLIC_KEY_SESSION).toBe(recordCase.publicKeyHex);
    expect(noLeftoverCiphertext(parsed, { SN_DB_KEY: recordCase.value })).toBe(true);
  }
});

test("a golden record decrypts under any field name — the format binds no associated data", () => {
  // THE DISCLOSED WEAKNESS, pinned on the TS side exactly as the Rust side
  // pins it (`records_are_not_bound_to_field_names_in_this_format`): dotenvx
  // records carry no AAD, so a record moved between field names still
  // decrypts. SECURITY.md discloses this. Structural guards remain: the
  // loader rejects any key outside the session contract, and the server
  // validates every credential.
  const recordCase = vectors.recordCases.find((entry) => entry.name === "cookie-shaped") ?? vectors.recordCases[0]!;
  const swapped = quietly(() =>
    parse(recordWrapper(recordCase.publicKeyHex, "SN_REFRESH_TOKEN", recordCase.value), {
      privateKey: recordCase.privateKeyHex,
    }),
  );
  expect(swapped.SN_REFRESH_TOKEN).toBe(recordCase.plaintext);
});

test("a wrong private key fails closed on the negative golden vectors", () => {
  const negative = vectors.recordCases.filter((entry) => entry.negativePrivateKeyHex !== undefined);
  expect(negative.length).toBeGreaterThanOrEqual(1);
  for (const recordCase of negative) {
    expect(recordCase.negativeKeyMustFail).toBe(true);
    // dotenvx's parse does not throw on a wrong key — it hands back the raw
    // `encrypted:` strings. Either the throw or the leftover ciphertext is
    // failing closed; a decrypted value is not.
    const value = quietly(() => {
      try {
        const parsed = parse(recordWrapper(recordCase.publicKeyHex, "SN_DB_KEY", recordCase.value), {
          privateKey: recordCase.negativePrivateKeyHex!,
        });
        return parsed.SN_DB_KEY ?? "";
      } catch {
        return null; // throwing is failing closed
      }
    });
    expect(value === null || value.startsWith("encrypted:")).toBe(true);
  }
});

test("the pinned library parses and decrypts every golden session file to its recorded values", () => {
  expect(vectors.fileCases.length).toBe(2);
  for (const fileCase of vectors.fileCases) {
    const parsed = quietly(() => parse(fileCase.sessionFile, { privateKey: fileCase.privateKeyHex }));
    expect(parsed.DOTENV_PUBLIC_KEY_SESSION).toBe(fileCase.publicKeyHex);
    for (const [key, value] of Object.entries(fileCase.secrets)) {
      expect(parsed[key]).toBe(value);
    }
    const records: Record<string, string> = {};
    for (const line of fileCase.sessionFile.split("\n")) {
      const match = line.match(/^([A-Z0-9_]+)="(encrypted:[^"]+)"/);
      if (match) records[match[1]!] = match[2]!;
    }
    expect(Object.keys(records).length).toBeGreaterThanOrEqual(1);
    expect(noLeftoverCiphertext(parsed, records)).toBe(true);
  }
});

test("both .env.keys custody styles hand the TS reader the session private key", () => {
  // The Rust save writes the sns style (`# dotenvx private key for
  // .env.session` + the bare key line); a `dotenvx set` bootstrap writes the
  // armored-banner style. Whatever wrote the file, the TS reader must
  // extract the same scalar — the custody half of the shared contract.
  const dir = mkdtempSync(join(tmpdir(), "sns-vectorkeys-"));
  try {
    withConfigDir(dir, () => {
      ensureConfigDir();
      const styles = new Set<string>();
      for (const fileCase of vectors.fileCases) {
        styles.add(fileCase.keysFileStyle);
        writeFileSync(keysPath(), fileCase.keysFile, { mode: 0o600 });
        expect(readPrivateKeyFile()).toBe(fileCase.privateKeyHex);
      }
      expect(styles).toEqual(new Set(["sns", "dotenvx"]));
    });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
