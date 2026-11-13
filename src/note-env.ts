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
 * into a newline, and no backslash sequence protects a closing quote. In an
 * unquoted value a whitespace-preceded `#` starts a comment; a bare `#` is
 * literal. After a closing quote a `#` tail is a comment too; anything else
 * there is ignored. An unclosed quote discards the assignment and parsing
 * resumes on the next line.
 *
 * `scanNote` runs the same walk and additionally returns each assignment's
 * trailing comment (comments never enter values, so they never reach the
 * clipboard) and the skipped lines as the note's prose, for views that show
 * keys without values. Callers that only want the settings pass
 * `{ prose: false }` — list and search parse every cached note and never
 * show prose.
 */

const KEY_CHAR = /[A-Za-z0-9_.-]/;
const COMMENT = /(^|\s)#/;

/** Result entries are keyed by first appearance, with last assignment winning. */
export function parseNoteSettings(text: string): Map<string, string> {
  return scanNote(text, { prose: false }).settings;
}

export type NoteScan = {
  /** Parsed settings, keyed by first appearance, last assignment winning. */
  settings: Map<string, string>;
  /**
   * Trailing `# …` comments, keyed like the settings and stripped from every
   * value. Present only when the winning assignment carried one: a duplicate
   * key whose last occurrence has no comment keeps no stale comment.
   */
  comments: Map<string, string>;
  /**
   * The lines the parser skipped, verbatim and in order — the note's prose.
   * Continuation lines of a multi-line quoted value are part of that value and
   * never appear here, and neither does a line whose assignment never closed
   * its quote (a half-written secret stays out of the description).
   */
  prose: string;
};

/**
 * One walk that yields the keys, their comments, and — unless `prose: false` —
 * the skipped lines, so `sns show`'s key inventory can never disagree with
 * `sns copy`'s lookup.
 */
export function scanNote(text: string, options: { prose?: boolean } = {}): NoteScan {
  const settings = new Map<string, string>();
  const comments = new Map<string, string>();
  const prose = options.prose === false ? null : ([] as string[]);
  let i = 0;
  while (i < text.length) {
    // On success tryAssignment returns the start of the next line; when the
    // line is prose or its quote never closes it returns null, and resuming
    // at the next line is the permissive fallback either way.
    const next = tryAssignment(text, i, settings, comments);
    if (next !== null) {
      i = next;
      continue;
    }
    const lineEnd = lineEndAfter(text, i);
    // tryAssignment returned null on a line that does start an assignment
    // only when its quote never closed — that line is not prose either.
    if (prose !== null && !assignmentStartsAt(text, i)) prose.push(text.slice(i, lineEnd));
    i = lineEnd;
  }
  return { settings, comments, prose: prose === null ? "" : prose.join("") };
}

/** Whether a line begins `key =` (blanks, optional export, key charset). */
function assignmentStartsAt(text: string, start: number): boolean {
  let i = start;
  while (isBlank(text[i])) i++;
  if (isExportToken(text, i)) i += "export".length;
  while (isBlank(text[i])) i++;
  const keyStart = i;
  while (isKeyChar(text[i])) i++;
  if (i === keyStart) return false;
  while (isBlank(text[i])) i++;
  return text[i] === "=";
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
function tryAssignment(
  text: string,
  start: number,
  settings: Map<string, string>,
  comments: Map<string, string>,
): number | null {
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
  // the winning assignment's comment (or absence of one) wins with it
  if (parsed.comment === null) comments.delete(key);
  else comments.set(key, parsed.comment);
  return lineEndAfter(text, parsed.end);
}

/** Index past the next newline (or end of text), so scanning resumes at a line boundary. */
function lineEndAfter(text: string, i: number): number {
  const nl = text.indexOf("\n", i);
  return nl === -1 ? text.length : nl + 1;
}

type Assignment = { value: string; comment: string | null; end: number };

/** The `# …` tail of a line, trimmed; null when the line carries no comment. */
function commentOn(line: string): string | null {
  const match = COMMENT.exec(line);
  return match === null ? null : line.slice(match.index + match[0].length - 1).trim();
}

/** Unquoted value: rest of the line, comment-truncated, whitespace-trimmed. */
function readUnquoted(text: string, start: number): Assignment {
  const nl = text.indexOf("\n", start);
  const line = text.slice(start, nl === -1 ? undefined : nl);
  return { value: line.slice(0, COMMENT.exec(line)?.index).trim(), comment: commentOn(line), end: nl === -1 ? text.length : nl };
}

/**
 * Quoted value: real line breaks preserved; `\n` unescaped in double quotes
 * only; the first matching quote closes (no backslash protects it). Returns
 * null when the quote never closes before the end of the text. A `#` tail on
 * the same line after the closing quote is the assignment's comment.
 */
function readQuoted(text: string, start: number, quote: string): Assignment | null {
  const close = text.indexOf(quote, start + 1);
  if (close === -1) return null;
  const raw = text.slice(start + 1, close);
  const nl = text.indexOf("\n", close + 1);
  const tail = text.slice(close + 1, nl === -1 ? undefined : nl);
  return { value: quote === '"' ? raw.replaceAll("\\n", "\n") : raw, comment: commentOn(tail), end: close + 1 };
}
