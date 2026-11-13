import { intro, outro } from "@clack/prompts";
import pc from "picocolors";
import { existsSync } from "node:fs";
import { UserError } from "../errors.ts";
import { createApi, randomDbKey } from "../sn-api.ts";
import { readPlainConfig, sessionPath, writePlainConfig } from "../paths.ts";
import { loadSession, saveSession, type SessionSecrets } from "../session-file.ts";
import { promptLine, promptSecret } from "./prompt.ts";
import { pullNotes, syncSummary } from "./sync.ts";

export async function loginCommand(): Promise<void> {
  intro("sns login");
  const plain = readPlainConfig();
  let email = plain.email;
  if (email === "") email = await promptLine("Email");
  if (!email.includes("@")) throw new UserError("email looks wrong");
  writePlainConfig({ email, apiUrl: plain.apiUrl });

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
    throw new UserError(
      `this session belongs to ${existing.accountEmail} — run sns logout before logging in as ${email}`,
    );
  }
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
