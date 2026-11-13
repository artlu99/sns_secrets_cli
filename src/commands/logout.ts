import { intro, outro } from "@clack/prompts";
import { UserError } from "../errors.ts";
import { removeCacheFiles } from "../db.ts";
import { createApi } from "../sn-api.ts";
import { dbPath, readPlainConfig } from "../paths.ts";
import { deleteSession, loadSession } from "../session-file.ts";

export async function logoutCommand(_options: { deleteCache?: boolean } = {}): Promise<void> {
  intro("sns logout");
  const secrets = await loadSession();
  if (!secrets) throw new UserError("not logged in");
  const plain = readPlainConfig();
  const api = createApi(plain.apiUrl);
  let revoked = true;
  try {
    await api.logout(secrets);
  } catch (error) {
    revoked = false;
    const message = error instanceof Error ? error.message : "revoke failed";
    console.error(`server revoke failed (${message}); local session will still be deleted`);
  }
  await deleteSession();
  removeCacheFiles(dbPath());
  const cacheNote = " The encrypted cache was removed with the database key.";
  outro(
    revoked
      ? `session revoked and local secrets deleted.${cacheNote}`
      : `local secrets deleted; the server session may still be valid until it expires.${cacheNote}`,
  );
}
