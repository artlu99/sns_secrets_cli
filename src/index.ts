#!/usr/bin/env bun
import pc from "picocolors";
import { maybeClearStaleClipboard } from "./clipboard.ts";
import { scrubProcessEnv } from "./env.ts";
import { UserError } from "./errors.ts";
import { buildProgram } from "./program.ts";

scrubProcessEnv();
maybeClearStaleClipboard();

buildProgram().parseAsync(process.argv).catch((error: unknown) => {
  const message = error instanceof Error ? error.message : String(error);
  console.error(pc.red(message));
  if (process.env.SNS_DEBUG === "1" && error instanceof Error && !(error instanceof UserError)) {
    console.error(error.stack);
  }
  process.exitCode = 1;
});
