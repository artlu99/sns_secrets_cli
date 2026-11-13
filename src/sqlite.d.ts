declare module "better-sqlite3-multiple-ciphers" {
  interface RunResult {
    changes: number;
    lastInsertRowid: number | bigint;
  }

  interface Statement {
    run(...params: unknown[]): RunResult;
    get(...params: unknown[]): unknown;
    all(...params: unknown[]): unknown[];
  }

  class Database {
    constructor(filename?: string, options?: { readonly?: boolean; fileMustExist?: boolean; timeout?: number });
    prepare(source: string): Statement;
    exec(source: string): this;
    pragma(source: string, options?: { simple?: boolean }): unknown;
    transaction<F extends (...args: any[]) => unknown>(fn: F): F;
    close(): this;
  }

  export default Database;
}
