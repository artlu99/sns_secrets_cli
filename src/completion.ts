/**
 * Shell tab-completion for sns. `sns completion bash|zsh` prints a script;
 * the script calls `sns __complete --cword N -- word…` which prints one
 * candidate per line. Stages covered: subcommands, `show`/`copy` note ids,
 * and `copy`'s setting key.
 *
 * Candidates are only offered when the resolver accepts them, and the shell
 * scripts quote what they insert — a note titled "staging api" completes to
 * one shell word that `sns show staging api` resolves.
 */

import { existsSync } from "node:fs";
import type { CacheDb } from "./db.ts";
import { openDatabase } from "./db.ts";
import { noteSettings, resolveNote, visibleNoteRows } from "./notes.ts";
import { dbPath } from "./paths.ts";
import { loadSession } from "./session-file.ts";

export const COMPLETION_SHELLS = ["bash", "zsh"] as const;
export type CompletionShell = (typeof COMPLETION_SHELLS)[number];

/**
 * Keep in sync with the commander program built in src/program.ts — a test
 * in completion.test.ts pins the two together. `help` is commander's own.
 */
export const SUBCOMMANDS = [
  "doctor",
  "login",
  "logout",
  "purge",
  "sync",
  "tags",
  "list",
  "search",
  "show",
  "copy",
  "sink",
  "completion",
  "help",
] as const;

/** Upper bound on note candidates: shells get sluggish with huge COMPREPLY lists. */
const MAX_CANDIDATES = 100;

type Stage = {
  kind: "subcommands" | "shells" | "noteIds" | "keys" | "logoutFlag" | "none";
  partial: string;
  noteQuery?: string;
};

/**
 * Which completion stage the cursor is in. Argument slots count only non-flag
 * words, so `sns show --no-pager <TAB>` still fills the note slot; a `-`
 * word being typed gets no candidates (flag names are not offered).
 */
function stageFor(words: string[], cword: number): Stage {
  const index = Math.max(0, Math.min(cword, words.length));
  const partial = words[index] ?? "";
  // Drop the binary name so positions match `sns <cmd> …`.
  const args = words.slice(1);

  if (index <= 1) {
    return { kind: "subcommands", partial: index === 1 ? (args[0] ?? "") : (words[0] ?? "") };
  }
  if (partial.startsWith("-")) return { kind: "none", partial };

  let slot = 0;
  let current = -1;
  for (let offset = 1; offset < args.length; offset++) {
    const arg = args[offset]!;
    const isCurrent = offset === index - 1;
    if (arg.startsWith("-")) {
      if (isCurrent) break;
      continue;
    }
    if (isCurrent) {
      current = slot;
      break;
    }
    slot++;
  }
  if (current === -1) {
    if (index - 1 >= args.length) current = slot; // completing a brand-new word
    else return { kind: "none", partial };
  }

  const command = args[0] ?? "";
  if (command === "completion" && current === 0) return { kind: "shells", partial };
  if ((command === "show" || command === "copy" || command === "sink") && current === 0) {
    return { kind: "noteIds", partial };
  }
  if ((command === "copy" || command === "sink") && current === 1) {
    return { kind: "keys", partial, noteQuery: args[1] ?? "" };
  }
  if (command === "logout" && current === 0) return { kind: "logoutFlag", partial };
  return { kind: "none", partial };
}

/** Pure completer — pass a CacheDb in tests; omit to skip note/key candidates. */
export function completeArgv(words: string[], cword: number, db: CacheDb | null): string[] {
  return completeStage(stageFor(words, cword), db);
}

function completeStage(stage: Stage, db: CacheDb | null): string[] {
  switch (stage.kind) {
    case "subcommands":
      return filterPrefix(SUBCOMMANDS, stage.partial);
    case "shells":
      return filterPrefix(COMPLETION_SHELLS, stage.partial);
    case "noteIds":
      return filterPrefix(noteIdCandidates(db), stage.partial, { loose: true });
    case "keys":
      return filterPrefix(keyCandidates(db, stage.noteQuery ?? ""), stage.partial);
    case "logoutFlag":
      return filterPrefix(["--delete-cache"], stage.partial);
    case "none":
      return [];
  }
}

export async function completeWithCache(words: string[], cword: number): Promise<string[]> {
  const stage = stageFor(words, cword);
  // Constant stages answer without touching the session or the cache at all.
  const db = stage.kind === "noteIds" || stage.kind === "keys" ? await tryOpenCache() : null;
  try {
    return completeStage(stage, db);
  } finally {
    db?.close();
  }
}

export function completionScript(shell: CompletionShell): string {
  if (shell === "bash") return bashScript();
  return zshScript();
}

function noteIdCandidates(db: CacheDb | null): string[] {
  if (!db) return [];
  const rows = visibleNoteRows(db, ["Note"]);
  const titles = rows.map((row) => (row.title ?? "").trim().toLowerCase());
  const uuids = rows.map((row) => row.uuid.toLowerCase());
  // Offer only candidates the resolver accepts — same trim/case rules as
  // resolveByPrefix — so TAB never completes a word the command rejects as
  // ambiguous ("API Keys" when "API Keys Old" exists) or unmatchable.
  const resolves = (candidate: string): boolean => {
    const probe = candidate.toLowerCase();
    if (/^[0-9a-f-]{8,}$/i.test(candidate)) {
      const byUuid = uuids.filter((uuid) => uuid.startsWith(probe));
      if (byUuid.length === 1) return true;
      if (byUuid.length > 1) return false;
    }
    return titles.filter((title) => title.startsWith(probe)).length === 1;
  };

  const out: string[] = [];
  const seen = new Set<string>();
  for (const row of rows) {
    const title = (row.title ?? "").trim();
    if (title !== "" && !seen.has(title) && resolves(title)) {
      seen.add(title);
      out.push(title);
    }
    const short = row.uuid.slice(0, 8);
    if (!seen.has(short) && resolves(short)) {
      seen.add(short);
      out.push(short);
    }
    if (out.length >= MAX_CANDIDATES) break;
  }
  return out;
}

function keyCandidates(db: CacheDb | null, noteQuery: string): string[] {
  if (!db || noteQuery === "") return [];
  try {
    const row = resolveNote(db, noteQuery, { all: false });
    return [...noteSettings(row).keys()];
  } catch {
    return [];
  }
}

function filterPrefix(
  candidates: readonly string[],
  partial: string,
  options: { loose?: boolean } = {},
): string[] {
  if (partial === "") return [...candidates];
  if (options.loose) {
    // The resolver matches titles and uuid prefixes case-insensitively, so a
    // typed "sta" must still complete to "Staging". Setting keys stay
    // case-sensitive: planCopy matches them exactly.
    const needle = partial.toLowerCase();
    return candidates.filter((candidate) => candidate.toLowerCase().startsWith(needle));
  }
  return candidates.filter((candidate) => candidate.startsWith(partial));
}

async function tryOpenCache(): Promise<CacheDb | null> {
  try {
    if (!existsSync(dbPath())) return null;
    const secrets = await loadSession();
    if (!secrets) return null;
    return openDatabase(dbPath(), secrets.dbKey);
  } catch {
    return null;
  }
}

function bashScript(): string {
  return `# sns bash completion — eval "$(sns completion bash)"
_sns() {
  local cword=\${COMP_CWORD}
  local -a words=("\${COMP_WORDS[@]}")
  local out line
  out=$(sns __complete --cword="\$cword" -- "\${words[@]}" 2>/dev/null) || return
  COMPREPLY=()
  # %q quotes each candidate, so a title with spaces or metacharacters is
  # inserted as one shell word.
  while IFS= read -r line; do
    [[ -n "\$line" ]] && COMPREPLY+=("$(printf '%q' "\$line")")
  done <<<"\$out"
}
complete -o nospace -F _sns sns
`;
}

function zshScript(): string {
  return `# sns zsh completion — eval "$(sns completion zsh)"
_sns() {
  local -a out
  local cword=$((CURRENT - 1))
  out=("\${(@f)$(sns __complete --cword="\$cword" -- "\${words[@]}" 2>/dev/null)}")
  # No -Q: compadd must quote metacharacters on insertion, so a title with
  # spaces or parens lands as one escaped word.
  compadd -- "\${out[@]}"
}
# compdef is defined by compinit; load that first so the eval works anywhere
# in .zshrc.
if ! (( $+functions[compdef] )); then
  autoload -Uz compinit && compinit
fi
compdef _sns sns
`;
}
