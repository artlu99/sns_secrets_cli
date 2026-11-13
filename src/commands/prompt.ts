import { cancel, password, text } from "@clack/prompts";
import { UserError } from "../errors.ts";

export function unwrap<T>(value: T): Exclude<T, symbol> {
  if (typeof value === "symbol") {
    cancel("cancelled");
    process.exit(0);
  }
  return value as Exclude<T, symbol>;
}

export async function promptSecret(message: string): Promise<string> {
  const value = unwrap(await password({ message }));
  if (value.trim() === "") throw new UserError("empty input");
  return value;
}

export async function promptLine(message: string, placeholder?: string): Promise<string> {
  return unwrap(await text({ message, placeholder })).trim();
}
