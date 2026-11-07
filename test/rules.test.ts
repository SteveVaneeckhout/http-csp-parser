import { describe, expect, it } from "vitest";
import {
  ALL_RULES,
  ruleBroadScheme,
  ruleDeprecatedDirective,
  ruleDuplicateDirective,
  ruleDuplicateSource,
  ruleMissingDefaultOrScriptSrc,
  ruleMissingSourceList,
  ruleNoneWithOtherSources,
  ruleNoValueDirectiveWithArguments,
  ruleReportUriWithoutReportTo,
  ruleStrictDynamicHostIgnored,
  ruleUnknownDirective,
  ruleUnsafeInlineWithUnsafeEval,
  runRules,
} from "../src/rules.js";
import type { ParsedDirective } from "../src/types.js";

function dir(name: string, sources: ParsedDirective["sources"] = []): ParsedDirective {
  return { name, raw: name, sources };
}

describe("ruleDuplicateDirective", () => {
  it("flags second and later occurrences of the same directive", () => {
    const issues = ruleDuplicateDirective([
      dir("default-src"),
      dir("script-src"),
      dir("default-src"),
      dir("default-src"),
    ]);
    expect(issues).toHaveLength(2);
    expect(issues.every((i) => i.code === "duplicate-directive")).toBe(true);
  });

  it("returns no issues when each directive is unique", () => {
    const issues = ruleDuplicateDirective([dir("default-src"), dir("script-src")]);
    expect(issues).toEqual([]);
  });
});

describe("ruleDuplicateSource", () => {
  it("flags repeated sources within a directive (case-insensitive)", () => {
    const issues = ruleDuplicateSource([
      dir("default-src", [
        { raw: "https://example.com", kind: "host", host: "example.com" },
        { raw: "'self'", kind: "keyword", keyword: "'self'" },
        { raw: "HTTPS://EXAMPLE.COM", kind: "host", host: "example.com" },
        { raw: "'self'", kind: "keyword", keyword: "'self'" },
      ]),
    ]);
    expect(issues).toHaveLength(2);
    expect(issues.every((i) => i.code === "duplicate-source")).toBe(true);
  });

  it("emits only one warning per source even when repeated three or more times", () => {
    const issues = ruleDuplicateSource([
      dir("default-src", [
        { raw: "https://example.com", kind: "host", host: "example.com" },
        { raw: "https://example.com", kind: "host", host: "example.com" },
        { raw: "https://example.com", kind: "host", host: "example.com" },
        { raw: "https://example.com", kind: "host", host: "example.com" },
      ]),
    ]);
    expect(issues).toHaveLength(1);
    expect(issues[0]?.code).toBe("duplicate-source");
  });

  it("returns no issues when every source is unique", () => {
    const issues = ruleDuplicateSource([
      dir("default-src", [
        { raw: "'self'", kind: "keyword", keyword: "'self'" },
        { raw: "https://example.com", kind: "host", host: "example.com" },
      ]),
    ]);
    expect(issues).toEqual([]);
  });

  it("scopes duplicate detection to a single directive", () => {
    const issues = ruleDuplicateSource([
      dir("default-src", [{ raw: "'self'", kind: "keyword", keyword: "'self'" }]),
      dir("script-src", [{ raw: "'self'", kind: "keyword", keyword: "'self'" }]),
    ]);
    expect(issues).toEqual([]);
  });
});

describe("ruleUnknownDirective", () => {
  it("flags directives not in the known set", () => {
    const issues = ruleUnknownDirective([dir("widget-src")]);
    expect(issues).toHaveLength(1);
    expect(issues[0]?.code).toBe("unknown-directive");
  });

  it("does not flag known directives", () => {
    const issues = ruleUnknownDirective([dir("default-src")]);
    expect(issues).toEqual([]);
  });
});

describe("ruleNoneWithOtherSources", () => {
  it("flags 'none' mixed with other sources", () => {
    const issues = ruleNoneWithOtherSources([
      dir("default-src", [
        { raw: "'none'", kind: "none" },
        { raw: "'self'", kind: "keyword", keyword: "'self'" },
      ]),
    ]);
    expect(issues).toHaveLength(1);
    expect(issues[0]?.code).toBe("none-with-other-sources");
  });

  it("does not flag 'none' alone", () => {
    const issues = ruleNoneWithOtherSources([
      dir("default-src", [{ raw: "'none'", kind: "none" }]),
    ]);
    expect(issues).toEqual([]);
  });

  it("does not flag a directive without 'none'", () => {
    const issues = ruleNoneWithOtherSources([
      dir("default-src", [{ raw: "'self'", kind: "keyword", keyword: "'self'" }]),
    ]);
    expect(issues).toEqual([]);
  });
});

describe("ruleNoValueDirectiveWithArguments", () => {
  it("flags arguments on a no-value directive", () => {
    const issues = ruleNoValueDirectiveWithArguments([
      dir("upgrade-insecure-requests", [{ raw: "'self'", kind: "keyword", keyword: "'self'" }]),
    ]);
    expect(issues).toHaveLength(1);
    expect(issues[0]?.code).toBe("no-value-directive-with-arguments");
  });

  it("does not flag a no-value directive without arguments", () => {
    const issues = ruleNoValueDirectiveWithArguments([dir("upgrade-insecure-requests")]);
    expect(issues).toEqual([]);
  });

  it("ignores directives that accept arguments", () => {
    const issues = ruleNoValueDirectiveWithArguments([
      dir("default-src", [{ raw: "'self'", kind: "keyword", keyword: "'self'" }]),
    ]);
    expect(issues).toEqual([]);
  });
});

describe("ruleMissingSourceList", () => {
  it("flags a source-list directive with no sources", () => {
    const issues = ruleMissingSourceList([dir("default-src")]);
    expect(issues).toHaveLength(1);
    expect(issues[0]?.code).toBe("missing-source-list");
  });

  it("does not flag a source-list directive with at least one source", () => {
    const issues = ruleMissingSourceList([
      dir("default-src", [{ raw: "'self'", kind: "keyword", keyword: "'self'" }]),
    ]);
    expect(issues).toEqual([]);
  });

  it("does not flag a no-value directive with no sources", () => {
    const issues = ruleMissingSourceList([dir("upgrade-insecure-requests")]);
    expect(issues).toEqual([]);
  });
});

describe("ruleDeprecatedDirective", () => {
  it("flags deprecated directives", () => {
    const issues = ruleDeprecatedDirective([dir("referrer"), dir("plugin-types")]);
    expect(issues).toHaveLength(2);
    expect(issues.every((i) => i.code === "deprecated-directive")).toBe(true);
  });

  it("leaves report-uri to ruleReportUriWithoutReportTo", () => {
    expect(ruleDeprecatedDirective([dir("report-uri")])).toEqual([]);
  });

  it("does not flag current directives", () => {
    const issues = ruleDeprecatedDirective([dir("default-src")]);
    expect(issues).toEqual([]);
  });
});

describe("ruleReportUriWithoutReportTo", () => {
  it("warns when report-uri is used without report-to", () => {
    const issues = ruleReportUriWithoutReportTo([dir("default-src"), dir("report-uri")]);
    expect(issues).toHaveLength(1);
    expect(issues[0]?.code).toBe("report-uri-without-report-to");
    expect(issues[0]?.level).toBe("warning");
    expect(issues[0]?.directive).toBe("report-uri");
  });

  it("does not warn when report-uri is paired with report-to", () => {
    expect(ruleReportUriWithoutReportTo([dir("report-uri"), dir("report-to")])).toEqual([]);
    expect(ruleReportUriWithoutReportTo([dir("report-to"), dir("report-uri")])).toEqual([]);
  });

  it("does not warn when only report-to is used", () => {
    expect(ruleReportUriWithoutReportTo([dir("report-to")])).toEqual([]);
  });

  it("does not warn when neither reporting directive is used", () => {
    expect(ruleReportUriWithoutReportTo([dir("default-src")])).toEqual([]);
  });
});

describe("ruleMissingDefaultOrScriptSrc", () => {
  it("flags policy without default-src or script-src", () => {
    const issues = ruleMissingDefaultOrScriptSrc([dir("img-src")]);
    expect(issues).toHaveLength(1);
    expect(issues[0]?.code).toBe("missing-default-src-or-script-src");
  });

  it("does not flag policy with default-src", () => {
    const issues = ruleMissingDefaultOrScriptSrc([dir("default-src")]);
    expect(issues).toEqual([]);
  });

  it("does not flag policy with script-src", () => {
    const issues = ruleMissingDefaultOrScriptSrc([dir("script-src")]);
    expect(issues).toEqual([]);
  });

  it("returns no issues for an empty directive list (avoids false positives on parse failure)", () => {
    const issues = ruleMissingDefaultOrScriptSrc([]);
    expect(issues).toEqual([]);
  });
});

describe("ruleStrictDynamicHostIgnored", () => {
  it("flags host and scheme sources alongside 'strict-dynamic'", () => {
    const issues = ruleStrictDynamicHostIgnored([
      dir("script-src", [
        { raw: "'strict-dynamic'", kind: "keyword", keyword: "'strict-dynamic'" },
        { raw: "https://cdn.example.com", kind: "host", host: "cdn.example.com" },
        { raw: "https:", kind: "scheme", scheme: "https" },
        { raw: "'self'", kind: "keyword", keyword: "'self'" },
      ]),
    ]);
    expect(issues).toHaveLength(2);
    expect(issues.every((i) => i.code === "strict-dynamic-host-ignored")).toBe(true);
  });

  it("does not flag a directive without 'strict-dynamic'", () => {
    const issues = ruleStrictDynamicHostIgnored([
      dir("script-src", [
        { raw: "https://cdn.example.com", kind: "host", host: "cdn.example.com" },
      ]),
    ]);
    expect(issues).toEqual([]);
  });

  it("does not flag 'strict-dynamic' alone with non-host keywords", () => {
    const issues = ruleStrictDynamicHostIgnored([
      dir("script-src", [
        { raw: "'strict-dynamic'", kind: "keyword", keyword: "'strict-dynamic'" },
        { raw: "'self'", kind: "keyword", keyword: "'self'" },
      ]),
    ]);
    expect(issues).toEqual([]);
  });
});

describe("ruleUnsafeInlineWithUnsafeEval", () => {
  it("flags a directive that contains both unsafe-inline and unsafe-eval", () => {
    const issues = ruleUnsafeInlineWithUnsafeEval([
      dir("script-src", [
        { raw: "'unsafe-inline'", kind: "keyword", keyword: "'unsafe-inline'" },
        { raw: "'unsafe-eval'", kind: "keyword", keyword: "'unsafe-eval'" },
      ]),
    ]);
    expect(issues).toHaveLength(1);
    expect(issues[0]?.code).toBe("unsafe-inline-with-unsafe-eval");
    expect(issues[0]?.directive).toBe("script-src");
  });

  it("does not flag unsafe-inline alone", () => {
    const issues = ruleUnsafeInlineWithUnsafeEval([
      dir("script-src", [{ raw: "'unsafe-inline'", kind: "keyword", keyword: "'unsafe-inline'" }]),
    ]);
    expect(issues).toEqual([]);
  });

  it("does not flag unsafe-eval alone", () => {
    const issues = ruleUnsafeInlineWithUnsafeEval([
      dir("script-src", [{ raw: "'unsafe-eval'", kind: "keyword", keyword: "'unsafe-eval'" }]),
    ]);
    expect(issues).toEqual([]);
  });

  it("does not flag a directive that omits both", () => {
    const issues = ruleUnsafeInlineWithUnsafeEval([
      dir("script-src", [{ raw: "'self'", kind: "keyword", keyword: "'self'" }]),
    ]);
    expect(issues).toEqual([]);
  });
});

describe("ruleBroadScheme", () => {
  it("flags https: scheme inside a fetch directive", () => {
    const issues = ruleBroadScheme([
      dir("script-src", [{ raw: "https:", kind: "scheme", scheme: "https" }]),
    ]);
    expect(issues).toHaveLength(1);
    expect(issues[0]?.code).toBe("broad-scheme");
  });

  it("flags http: scheme inside a fetch directive", () => {
    const issues = ruleBroadScheme([
      dir("img-src", [{ raw: "http:", kind: "scheme", scheme: "http" }]),
    ]);
    expect(issues).toHaveLength(1);
  });

  it("flags ws: and wss: schemes inside a fetch directive", () => {
    const issues = ruleBroadScheme([
      dir("connect-src", [
        { raw: "ws:", kind: "scheme", scheme: "ws" },
        { raw: "wss:", kind: "scheme", scheme: "wss" },
      ]),
    ]);
    expect(issues.map((i) => i.source)).toEqual(["ws:", "wss:"]);
    expect(issues[0]?.message).toContain("any host over ws");
  });

  it("does not flag a ws/wss host source", () => {
    const issues = ruleBroadScheme([
      dir("connect-src", [
        { raw: "wss://ws.example.com", kind: "host", scheme: "wss", host: "ws.example.com" },
      ]),
    ]);
    expect(issues).toEqual([]);
  });

  it("does not flag narrow schemes like data:", () => {
    const issues = ruleBroadScheme([
      dir("img-src", [{ raw: "data:", kind: "scheme", scheme: "data" }]),
    ]);
    expect(issues).toEqual([]);
  });

  it("ignores schemes outside fetch directives", () => {
    const issues = ruleBroadScheme([
      dir("base-uri", [{ raw: "https:", kind: "scheme", scheme: "https" }]),
    ]);
    expect(issues).toEqual([]);
  });

  it("ignores fetch directives that do not include a scheme source", () => {
    const issues = ruleBroadScheme([
      dir("script-src", [{ raw: "'self'", kind: "keyword", keyword: "'self'" }]),
    ]);
    expect(issues).toEqual([]);
  });
});

describe("runRules / ALL_RULES", () => {
  it("aggregates issues from every registered rule", () => {
    const issues = runRules([dir("widget-src"), dir("widget-src")]);
    expect(issues.some((i) => i.code === "duplicate-directive")).toBe(true);
    expect(issues.some((i) => i.code === "unknown-directive")).toBe(true);
  });

  it("exposes the same number of rule functions in ALL_RULES", () => {
    expect(ALL_RULES.length).toBe(12);
  });
});
