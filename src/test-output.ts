import { spyOn } from "bun:test";

/**
 * Capture everything a command prints (console.log/error and raw stdout) so
 * tests can assert a secret never appears in output. Shared by command test
 * suites; restore() in a `finally`.
 */
export function outputSpy() {
  const chunks: string[] = [];
  const log = spyOn(console, "log").mockImplementation((...args: unknown[]) => {
    chunks.push(args.map(String).join(" "));
  });
  const err = spyOn(console, "error").mockImplementation((...args: unknown[]) => {
    chunks.push(args.map(String).join(" "));
  });
  const out = spyOn(process.stdout, "write").mockImplementation((chunk: any) => {
    chunks.push(String(chunk));
    return true;
  });
  return {
    text: () => chunks.join("\n"),
    restore() {
      log.mockRestore();
      err.mockRestore();
      out.mockRestore();
    },
  };
}
