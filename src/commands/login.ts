import { intro, outro } from "@clack/prompts";
import pc from "picocolors";
import { existsSync } from "node:fs";
import { UserError } from "../errors.ts";
import { createApi, randomDbKey } from "../sn-api.ts";
import { readPlainConfig, sessionPath, writePlainConfig } from "../paths.ts";
import { loadSession, saveSession, type SessionSecrets } from "../session-file.ts";
import { clearSession } from "./logout.ts";
import { promptConfirm, promptLine, promptSecret } from "./prompt.ts";
import { pullNotes, syncSummary } from "./sync.ts";

export async function loginCommand(): Promise<void> {
  // The prompts below need a real terminal: clack never resolves on EOF, so a
  // piped run would stall forever at the password prompt — and a piped line
  // gets appended to the prefilled email. Fail fast instead. (The Rust port
  // reads plain stdin lines and its password prompt uses /dev/tty, so it
  // degrades gracefully without this guard.)
  if (!process.stdin.isTTY) {
    throw new UserError("`sns login` is interactive — run it in a terminal");
  }
  intro("sns login");
  const plain = readPlainConfig();
  // Always confirm the email so a saved SN_EMAIL is not a dead end — Enter
  // keeps it; typing another address is the escape hatch for a different account.
  const email = await promptLine("Email", {
    initialValue: plain.email || undefined,
    placeholder: plain.email ? undefined : "you@example.com",
  });
  if (!email.includes("@")) throw new UserError("email looks wrong");

  const password = await promptSecret("Account password");
  const mfaCode = () => promptSecret("Two-factor code");
  let existing: SessionSecrets | null = null;
  if (existsSync(sessionPath())) {
    try {
      existing = await loadSession();
    } catch (error) {
      // `sns login` is the recovery path for a broken session — it must not
      // fail on the very state it exists to fix.
      const reason = error instanceof Error ? error.message : "unreadable session file";
      console.error(pc.yellow(`the existing session is unreadable and will be replaced (${reason})`));
    }
  }
  if (existing?.accountEmail && existing.accountEmail !== email) {
    const switchAccount = await promptConfirm(
      `session belongs to ${existing.accountEmail} — logout and continue as ${email}?`,
      false,
    );
    if (!switchAccount) {
      throw new UserError(
        `this session belongs to ${existing.accountEmail} — run sns logout before logging in as ${email}`,
      );
    }
    await clearSession({ deleteCache: false });
    existing = null;
  }
  // The typed email is persisted only once the account switch is settled —
  // declining must leave .env pointing at the account still logged in.
  writePlainConfig({ email, apiUrl: plain.apiUrl });

  const dbKey = existing?.dbKey ?? randomDbKey();
  const api = createApi(plain.apiUrl);
  const { secrets, masterKey } = await api.login(email, password, mfaCode, dbKey);
  secrets.accountEmail = email;
  const stored = await saveSession(secrets);
  let synced: Awaited<ReturnType<typeof pullNotes>>;
  try {
    synced = await pullNotes({ secrets, api, email, masterKey });
  } catch (error) {
    const message = error instanceof Error ? error.message : "sync failed";
    throw new UserError(`session saved, but sync failed: ${message}\nnext: sns sync`);
  }

  const where = stored.keychain
    ? "dotenvx key is in the OS keychain"
    : "no secret service here — dotenvx key is in .env.keys (mode 0600)";
  outro(`session saved. ${where}\n${syncSummary(synced.report, synced.replaced)}`);
}
