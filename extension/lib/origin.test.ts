import { describe, expect, test } from "bun:test";
import { DEFAULT_ORIGIN_RULE_ID, DYNAMIC_ORIGIN_RULE_ID, originRuleForApi, removeOriginRule } from "./origin.ts";

const EXTENSION_ID = "abcdefghijklmnopabcdefghijklmnop";

describe("origin rules", () => {
  test("custom API origin gets a dynamic remove-Origin rule for its host", () => {
    const rule = originRuleForApi("https://sn.example.dev", EXTENSION_ID);
    expect(rule).toEqual({
      id: DYNAMIC_ORIGIN_RULE_ID,
      priority: 1,
      action: { type: "modifyHeaders", requestHeaders: [{ header: "Origin", operation: "remove" }] },
      condition: {
        requestDomains: ["sn.example.dev"],
        initiatorDomains: [EXTENSION_ID],
        resourceTypes: ["xmlhttprequest"],
      },
    });
  });

  test("api.standardnotes.com needs no dynamic rule (the worker's default rule covers it)", () => {
    expect(originRuleForApi("https://api.standardnotes.com", EXTENSION_ID)).toBeNull();
    expect(originRuleForApi("https://api.standardnotes.com/", EXTENSION_ID)).toBeNull();
  });

  test("unparseable URLs produce no rule", () => {
    expect(originRuleForApi("not a url", EXTENSION_ID)).toBeNull();
  });

  test("the default rule targets the hosted API, scoped to extension-initiated requests", () => {
    const rule = removeOriginRule(DEFAULT_ORIGIN_RULE_ID, ["api.standardnotes.com"], [EXTENSION_ID]);
    expect(rule.id).toBe(1);
    expect(rule.action.requestHeaders).toEqual([{ header: "Origin", operation: "remove" }]);
    expect(rule.condition.requestDomains).toEqual(["api.standardnotes.com"]);
    expect(rule.condition.initiatorDomains).toEqual([EXTENSION_ID]);
  });

  test("rule shape strips only Origin, only for XHR, only from the given initiators", () => {
    const rule = removeOriginRule(9, ["a.test", "b.test"], ["ext-one", "ext-two"]);
    expect(rule.action.requestHeaders).toEqual([{ header: "Origin", operation: "remove" }]);
    expect(rule.condition.requestDomains).toEqual(["a.test", "b.test"]);
    expect(rule.condition.initiatorDomains).toEqual(["ext-one", "ext-two"]);
    expect(rule.condition.resourceTypes).toEqual(["xmlhttprequest"]);
  });
});
