#!/usr/bin/env bun
import { Command } from "commander";
import pc from "picocolors";
import { maybeClearStaleClipboard } from "./clipboard.ts";
import { browseCommand } from "./commands/browse.ts";
import { copyCommand } from "./commands/copy.ts";
import { doctorCommand } from "./commands/doctor.ts";
import { listCommand } from "./commands/list.ts";
import { loginCommand } from "./commands/login.ts";
import { logoutCommand } from "./commands/logout.ts";
import { searchCommand } from "./commands/search.ts";
import { showCommand } from "./commands/show.ts";
import { syncCommand } from "./commands/sync.ts";
import { UserError } from "./errors.ts";
import { scrubProcessEnv } from "./env.ts";

scrubProcessEnv();
maybeClearStaleClipboard();

const program = new Command();
program
  .name("sns")
  .description("Read Standard Notes with an encrypted local cache")
  .version("0.1.0")
  .action(browseCommand);

program.command("doctor").description("check runtime, keychain, session, and cache").action(async () => {
  process.exitCode = await doctorCommand();
});

program.command("login").description("log in and sync notes into the encrypted cache").action(loginCommand);

program
  .command("logout")
  .description("revoke the session and delete local secrets")
  .option("--delete-cache", "also delete the encrypted cache")
  .action(async (options: { deleteCache?: boolean }) => {
    await logoutCommand(options);
  });

program.command("sync").description("pull and decrypt notes into the encrypted cache").action(syncCommand);

program
  .command("list")
  .description("list notes from the cache")
  .option("--type <content_type>", "filter by content type, e.g. Note")
  .option("--limit <n>", "max rows", "100")
  .option("--all", "include key-bearing items")
  .action(listCommand);

program
  .command("search")
  .description("search decrypted title and content")
  .argument("<query>")
  .option("--regex", "treat the query as a regular expression")
  .option("--limit <n>", "max hits", "50")
  .option("--all", "include key-bearing items")
  .action(searchCommand);

program
  .command("show")
  .description("show a note in a pager (stdin; nothing is written to disk)")
  .argument("<id>", "uuid or title prefix")
  .option("--no-pager", "print plaintext to stdout")
  .action(async (id: string, options: { pager?: boolean }) => {
    await showCommand(id, { noPager: options.pager === false });
  });

program
  .command("copy")
  .description("copy a note to the clipboard via OSC 52; clears in 30s")
  .argument("<id>", "uuid or title prefix")
  .action(copyCommand);

program.parseAsync(process.argv).catch((error: unknown) => {
  const message = error instanceof Error ? error.message : String(error);
  console.error(pc.red(message));
  if (process.env.SNS_DEBUG === "1" && error instanceof Error && !(error instanceof UserError)) {
    console.error(error.stack);
  }
  process.exitCode = 1;
});
