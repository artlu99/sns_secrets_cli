import { describe, expect, test } from "bun:test";
import { DYNAMIC_ORIGIN_RULE_ID, originRuleForApi, removeOriginRule } from "./origin.ts";

describe("origin rules", () => {
  test("custom API origin gets a dynamic remove-Origin rule for its host", () => {
    const rule = originRuleForApi("https://sn.example.dev");
    expect(rule).toEqual({
      id: DYNAMIC_ORIGIN_RULE_ID,
      priority: 1,
      action: { type: "modifyHeaders", requestHeaders: [{ header: "Origin", operation: "remove" }] },
      condition: { requestDomains: ["sn.example.dev"], resourceTypes: ["xmlhttprequest"] },
    });
  });

  test("api.standardnotes.com needs no dynamic rule (static ruleset covers it)", () => {
    expect(originRuleForApi("https://api.standardnotes.com")).toBeNull();
    expect(originRuleForApi("https://api.standardnotes.com/")).toBeNull();
  });

  test("unparseable URLs produce no rule", () => {
    expect(originRuleForApi("not a url")).toBeNull();
  });

  test("rule shape strips only Origin, only for XHR", () => {
    const rule = removeOriginRule(9, ["a.test", "b.test"]);
    expect(rule.action.requestHeaders).toEqual([{ header: "Origin", operation: "remove" }]);
    expect(rule.condition.requestDomains).toEqual(["a.test", "b.test"]);
    expect(rule.condition.resourceTypes).toEqual(["xmlhttprequest"]);
  });
});
