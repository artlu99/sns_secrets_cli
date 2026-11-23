#!/usr/bin/env bun
import pc from "picocolors";
import { maybeClearStaleClipboard } from "./clipboard.ts";
import { scrubProcessEnv } from "./env.ts";
import { UserError } from "./errors.ts";
import { sanitizeText } from "./notes.ts";
import { buildProgram } from "./program.ts";

scrubProcessEnv();
maybeClearStaleClipboard();

buildProgram().parseAsync(process.argv).catch((error: unknown) => {
  // every command's failure prints through this one boundary: server error
  // text (ApiError summaries) and note-derived text (titles in UserErrors)
  // are sanitized before they touch the terminal
  const message = sanitizeText(error instanceof Error ? error.message : String(error));
  console.error(pc.red(message));
  if (process.env.SNS_DEBUG === "1" && error instanceof Error && !(error instanceof UserError)) {
    console.error(sanitizeText(error.stack ?? ""));
  }
  process.exitCode = 1;
});
