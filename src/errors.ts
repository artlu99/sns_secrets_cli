/** Failures we can explain in one line. The message must not contain secrets. */
export class UserError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "UserError";
  }
}
