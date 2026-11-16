import { Command } from "commander";
import { browseCommand } from "./commands/browse.ts";
import { copyCommand } from "./commands/copy.ts";
import { doctorCommand } from "./commands/doctor.ts";
import { listCommand } from "./commands/list.ts";
import { loginCommand } from "./commands/login.ts";
import { logoutCommand } from "./commands/logout.ts";
import { purgeCommand } from "./commands/purge.ts";
import { searchCommand } from "./commands/search.ts";
import { showCommand } from "./commands/show.ts";
import { sinkCommand } from "./commands/sink.ts";
import { syncCommand } from "./commands/sync.ts";
import { tagsCommand } from "./commands/tags.ts";
import {
  COMPLETION_SHELLS,
  completeWithCache,
  completionScript,
  type CompletionShell,
} from "./completion.ts";
import { UserError } from "./errors.ts";
import { VERSION } from "./version.ts";

/**
 * The command surface, without runtime bootstrap (env scrubbing, the stale
 * clipboard sweep, or argv parsing) so tests can import it to pin things
 * like completion's subcommand list against the real definitions.
 */
export function buildProgram(): Command {
  const program = new Command();
  program
    .name("sns")
    .description("Read Standard Notes with an encrypted local cache; run with no command for an interactive picker")
    .version(VERSION)
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

  program
    .command("purge")
    .description("delete the entire local config directory (offline; never touches the server)")
    .option("-y, --yes", "skip the confirmation prompt (required when not a terminal)")
    .action(async (options: { yes?: boolean }) => {
      await purgeCommand(options);
    });

  program.command("sync").description("pull and decrypt notes into the encrypted cache").action(syncCommand);

  program.command("tags").description("list tags and folders (read-only)").action(tagsCommand);

  program
    .command("list")
    .description("list notes (env-style setting count per note; --all for everything)")
    .option("--type <content_type>", "filter by content type, e.g. Note")
    .option("--tag <name>", "only notes under this tag or folder")
    .option("--limit <n>", "max rows", "100")
    .option("--all", "list everything, including key-bearing items")
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
    .description("show a note's setting keys and prose (values stay in the cache)")
    .argument("<id>", "uuid or title prefix")
    .option("--no-pager", "print without paging")
    .action(async (id: string, options: { pager?: boolean }) => {
      await showCommand(id, { noPager: options.pager === false });
    });

  program
    .command("copy")
    .description("copy one setting value to the clipboard via OSC 52; clears in 30s")
    .argument("<id>", "uuid or title prefix")
    .argument("[key]", "exact setting name; omit to list the note's keys")
    .action(copyCommand);

  program
    .command("sink")
    .description("write one setting value to a 0600 file (agent handoff; the value is never displayed)")
    .argument("<id>", "uuid or title prefix")
    .argument("<key>", "exact setting name")
    .argument("<path>", "destination file (created 0600; must not exist without --force)")
    .option("--force", "overwrite an existing file (still 0600)")
    .action(async (id: string, key: string, path: string, options: { force?: boolean }) => {
      await sinkCommand(id, key, path, options);
    });

  program
    .command("completion")
    .description("print bash or zsh tab-completion script")
    .argument("<shell>", "bash or zsh")
    .action((shell: string) => {
      if (!(COMPLETION_SHELLS as readonly string[]).includes(shell)) {
        throw new UserError(`unknown shell ${JSON.stringify(shell)} — use bash or zsh`);
      }
      process.stdout.write(completionScript(shell as CompletionShell));
    });

  // Hidden: shell scripts call this. Prints one candidate per line.
  program
    .command("__complete", { hidden: true })
    .allowUnknownOption(true)
    .option("--cword <n>", "index into the word list (COMP_CWORD)", "0")
    .argument("[words...]", "COMP_WORDS / zsh words")
    .action(async (words: string[], options: { cword?: string }) => {
      const cword = Number(options.cword ?? "0");
      if (!Number.isInteger(cword) || cword < 0) throw new UserError("--cword must be a non-negative integer");
      const candidates = await completeWithCache(words, cword);
      if (candidates.length > 0) process.stdout.write(`${candidates.join("\n")}\n`);
    });

  return program;
}
