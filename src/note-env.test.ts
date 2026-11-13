import { expect, test } from "bun:test";
import { parseNoteSettings } from "./note-env.ts";

test("extracts KEY=VALUE settings and ignores the prose around them", () => {
  const note = [
    "Notes on my API setup.",
    "",
    "DB_HOST=localhost",
    "The retry policy lives in docs/retry.md.",
    "API_KEY=abc123",
    "Ask Alice about rate limits.",
  ].join("\n");
  expect(parseNoteSettings(note)).toEqual(
    new Map([
      ["DB_HOST", "localhost"],
      ["API_KEY", "abc123"],
    ]),
  );
});

test("keys are case-sensitive and kept verbatim", () => {
  const settings = parseNoteSettings("Token=a\nTOKEN=b");
  expect([...settings.keys()]).toEqual(["Token", "TOKEN"]);
  expect(settings.get("Token")).toBe("a");
  expect(settings.get("TOKEN")).toBe("b");
});

test("key charset is letters, digits, underscore, dot, dash", () => {
  const settings = parseNoteSettings("A_1=x\nkey-with-dashes=y\ndotted.key=z");
  expect(settings.get("A_1")).toBe("x");
  expect(settings.get("key-with-dashes")).toBe("y");
  expect(settings.get("dotted.key")).toBe("z");
});

test("no variable expansion: $HOME and ${FOO} stay literal", () => {
  const settings = parseNoteSettings(String.raw`FOO=$HOME` + "\n" + 'BAR=${FOO}' + "\n" + String.raw`PRICE=$19.99`);
  expect(settings.get("FOO")).toBe("$HOME");
  expect(settings.get("BAR")).toBe("${FOO}");
  expect(settings.get("PRICE")).toBe("$19.99");
});

test("all three quote styles keep real line breaks", () => {
  expect(parseNoteSettings('D="first\nsecond"').get("D")).toBe("first\nsecond");
  expect(parseNoteSettings(String.raw`S='keep \n literal` + "\nsecond'").get("S")).toBe(
    String.raw`keep \n literal` + "\nsecond",
  );
  expect(parseNoteSettings("B=`raw\ntext`").get("B")).toBe("raw\ntext");
});

test("\\n escape sequences become newlines only inside double quotes", () => {
  expect(parseNoteSettings(String.raw`A="l1\nl2"`).get("A")).toBe("l1\nl2");
  expect(parseNoteSettings(String.raw`A='l1\nl2'`).get("A")).toBe(String.raw`l1\nl2`);
  expect(parseNoteSettings(String.raw`A=` + "`l1\\nl2`").get("A")).toBe(String.raw`l1\nl2`);
});

test("anything after a closing quote on the same line is ignored", () => {
  const settings = parseNoteSettings('A="x" B=y');
  expect([...settings.keys()]).toEqual(["A"]);
  expect(settings.get("A")).toBe("x");
});

test("comments: whitespace-preceded # ends an unquoted value; bare # is literal; quoted # is always literal", () => {
  expect(parseNoteSettings("plain=value  # note").get("plain")).toBe("value");
  expect(parseNoteSettings("plain=# note").get("plain")).toBe("");
  expect(parseNoteSettings("plain=v#1").get("plain")).toBe("v#1");
  expect(parseNoteSettings('plain="a # b"').get("plain")).toBe("a # b");
  expect(parseNoteSettings('plain="a" # note').get("plain")).toBe("a");
});

test("exact duplicate keys: last wins, first-seen order", () => {
  const settings = parseNoteSettings("A=1\nB=2\nA=3");
  expect([...settings.keys()]).toEqual(["A", "B"]);
  expect(settings.get("A")).toBe("3");
});

test("an unclosed quote ignores that assignment and parsing continues", () => {
  const settings = parseNoteSettings('A="oops\nB=still-here');
  expect(settings.has("A")).toBe(false);
  expect(settings.get("B")).toBe("still-here");
});

test("export is skipped only before a valid assignment", () => {
  expect(parseNoteSettings("export DB_HOST=localhost").get("DB_HOST")).toBe("localhost");
  expect(parseNoteSettings("export is a shell builtin").size).toBe(0);
  expect(parseNoteSettings("exports = 5").get("exports")).toBe("5");
});

test("spaces and tabs around = and before the key are allowed", () => {
  const settings = parseNoteSettings("Title = With Spaces\n\tINDENTED=yes");
  expect(settings.get("Title")).toBe("With Spaces");
  expect(settings.get("INDENTED")).toBe("yes");
});

test("unquoted values are whitespace-trimmed and keep internal spacing", () => {
  expect(parseNoteSettings("KEY=  spaced  out  ").get("KEY")).toBe("spaced  out");
  expect(parseNoteSettings("KEY=").get("KEY")).toBe("");
});

test("= is the only separator; prose with colons is not an assignment", () => {
  expect(parseNoteSettings("Title: something").size).toBe(0);
  expect(parseNoteSettings("ratio 1:2 = fine").size).toBe(0);
  expect(parseNoteSettings("ratio=1:2").get("ratio")).toBe("1:2");
});

test("a URL on its own line is prose; a querystring after = is a value", () => {
  expect(parseNoteSettings("see https://example.com/a?b=c").size).toBe(0);
  expect(parseNoteSettings("url=https://example.com/a?b=c").get("url")).toBe("https://example.com/a?b=c");
});

test("parsing resumes on the line after a multi-line value", () => {
  const note = 'A="x\ny"\nB=z';
  const settings = parseNoteSettings(note);
  expect(settings.get("A")).toBe("x\ny");
  expect(settings.get("B")).toBe("z");
});

test("crlf notes parse the same as lf notes", () => {
  const settings = parseNoteSettings("A=one\r\nB=\"two\"\r\n");
  expect(settings.get("A")).toBe("one");
  expect(settings.get("B")).toBe("two");
});

test("an empty note and a note of pure prose yield an empty map", () => {
  expect(parseNoteSettings("").size).toBe(0);
  expect(parseNoteSettings("Just a paragraph.\n\nAnother one.").size).toBe(0);
});

test("a realistic mixed note parses to its settings", () => {
  const note = [
    "# deploy credentials",
    "",
    "These are the secrets for the staging deploy. Rotate quarterly.",
    "",
    "```",
    "export STAGING_URL=https://staging.example.test",
    'STAGING_TOKEN="s3cr3t\\nwith-newline"',
    "```",
    "",
    "DEPLOY_USER=deploy  # shared account",
    "NOTE = this key has spaces around the equals sign",
    "",
    "Talk to Alice before rotating.",
  ].join("\n");
  const settings = parseNoteSettings(note);
  expect(settings.get("STAGING_URL")).toBe("https://staging.example.test");
  expect(settings.get("STAGING_TOKEN")).toBe("s3cr3t\nwith-newline");
  expect(settings.get("DEPLOY_USER")).toBe("deploy");
  expect(settings.get("NOTE")).toBe("this key has spaces around the equals sign");
  expect(settings.size).toBe(4);
});
