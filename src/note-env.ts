/**
 * Parse `KEY=VALUE` settings out of the prose of a note.
 *
 * An assignment is recognized only at the start of a line (leading spaces and
 * tabs allowed): `=` is the only separator, with optional spaces/tabs around
 * it. Keys match `[\w.-]+` and are kept verbatim — case-sensitive, so `Token`
 * and `TOKEN` are distinct entries. Exact duplicates: last occurrence wins,
 * first-seen order. Nothing is ever expanded (`$HOME`, `${FOO}` stay literal)
 * and non-assignment lines are skipped without complaint.
 *
 * Values run to end of line unless quoted. All three quote styles span lines
 * with real line breaks preserved; only double quotes process the `\n` escape
 * into a newline, and no backslash sequence protects a closing quote. After a
 * closing quote the rest of the line is ignored. In an unquoted value a
 * whitespace-preceded `#` starts a comment; a bare `#` is literal. An unclosed
 * quote discards the assignment and parsing resumes on the next line.
 */

const KEY_CHAR = /[A-Za-z0-9_.-]/;
const COMMENT = /(^|\s)#/;

/** Result entries are keyed by first appearance, with last assignment winning. */
export function parseNoteSettings(text: string): Map<string, string> {
  const settings = new Map<string, string>();
  let i = 0;
  while (i < text.length) {
    // On success tryAssignment returns the start of the next line; when the
    // line is prose or its quote never closes it returns null, and resuming
    // at the next line is the permissive fallback either way.
    i = tryAssignment(text, i, settings) ?? lineEndAfter(text, i);
  }
  return settings;
}

/** Spaces and tabs only — a newline ends the key and `=` must be on the same line. */
function isBlank(ch: string | undefined): boolean {
  return ch === " " || ch === "\t";
}

/** `export` as a whole token followed by whitespace; `exports = 5` still keys on `exports`. */
function isExportToken(text: string, i: number): boolean {
  return text.startsWith("export", i) && isBlank(text[i + "export".length]);
}

function isKeyChar(ch: string | undefined): boolean {
  return ch !== undefined && KEY_CHAR.test(ch);
}

/**
 * Parse one assignment starting at a line boundary. On success returns the
 * start of the next line (the rest of the assignment's last line is ignored).
 * Returns null when the line is prose or the quote is unclosed.
 */
function tryAssignment(text: string, start: number, settings: Map<string, string>): number | null {
  let i = start;
  while (isBlank(text[i])) i++;
  if (isExportToken(text, i)) i += "export".length;
  while (isBlank(text[i])) i++;
  const keyStart = i;
  while (isKeyChar(text[i])) i++;
  if (i === keyStart) return null;
  const key = text.slice(keyStart, i);
  while (isBlank(text[i])) i++;
  if (text[i] !== "=") return null;
  i++;
  while (isBlank(text[i])) i++;
  const quote = text[i];
  const parsed = quote === '"' || quote === "'" || quote === "`" ? readQuoted(text, i, quote) : readUnquoted(text, i);
  if (parsed === null) return null; // unclosed quote: ignore the assignment
  settings.set(key, parsed.value);
  return lineEndAfter(text, parsed.end);
}

/** Index past the next newline (or end of text), so scanning resumes at a line boundary. */
function lineEndAfter(text: string, i: number): number {
  const nl = text.indexOf("\n", i);
  return nl === -1 ? text.length : nl + 1;
}

/** Unquoted value: rest of the line, comment-truncated, whitespace-trimmed. */
function readUnquoted(text: string, start: number): { value: string; end: number } {
  const nl = text.indexOf("\n", start);
  const line = text.slice(start, nl === -1 ? undefined : nl);
  return { value: line.slice(0, COMMENT.exec(line)?.index).trim(), end: nl === -1 ? text.length : nl };
}

/**
 * Quoted value: real line breaks preserved; `\n` unescaped in double quotes
 * only; the first matching quote closes (no backslash protects it). Returns
 * null when the quote never closes before the end of the text.
 */
function readQuoted(text: string, start: number, quote: string): { value: string; end: number } | null {
  const close = text.indexOf(quote, start + 1);
  if (close === -1) return null;
  const raw = text.slice(start + 1, close);
  return { value: quote === '"' ? raw.replaceAll("\\n", "\n") : raw, end: close + 1 };
}
