import { intro, outro } from "@clack/prompts";
import { existsSync } from "node:fs";
import { UserError } from "../errors.ts";
import { createApi, randomDbKey } from "../sn-api.ts";
import { readPlainConfig, sessionPath, writePlainConfig } from "../paths.ts";
import { loadSession, saveSession } from "../session-file.ts";
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
  const existing = existsSync(sessionPath()) ? await loadSession() : null;
  const dbKey = existing?.dbKey ?? randomDbKey();
  const api = createApi(plain.apiUrl);
  const { secrets, masterKey } = await api.login(email, password, mfaCode, dbKey);
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
