import { cancel, confirm, password, text } from "@clack/prompts";
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

export async function promptLine(
  message: string,
  options: { placeholder?: string; initialValue?: string } = {},
): Promise<string> {
  return unwrap(
    await text({
      message,
      placeholder: options.placeholder,
      initialValue: options.initialValue,
    }),
  ).trim();
}

export async function promptConfirm(message: string, initialValue = false): Promise<boolean> {
  return unwrap(await confirm({ message, initialValue }));
}
