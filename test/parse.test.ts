import { describe, expect, it } from "vitest";
import { parse } from "../src/parse.js";

describe("parse (end-to-end)", () => {
  it("parses a happy-path policy with no errors or warnings", () => {
    const result = parse(
      "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'",
    );
    expect(result.errors).toEqual([]);
    expect(result.warnings).toEqual([]);
    expect(result.directives).toHaveLength(4);
    expect(result.directives.map((d) => d.name)).toEqual([
      "default-src",
      "img-src",
      "style-src",
      "script-src",
    ]);
  });

  it("returns an empty-input error for an empty header", () => {
    const result = parse("");
    expect(result.errors).toHaveLength(1);
    expect(result.errors[0]?.code).toBe("empty-input");
    expect(result.directives).toEqual([]);
  });

  it("collects multiple errors and warnings from a poorly written policy", () => {
    const result = parse(
      "default-src 'self' 'unsafe-inline'; default-src 'none' 'self'; widget-src *; script-src 'unsafe-eval' https:; upgrade-insecure-requests https:; report-uri /r",
    );
    const codes = new Set([
      ...result.errors.map((e) => e.code),
      ...result.warnings.map((w) => w.code),
    ]);
    expect(codes.has("duplicate-directive")).toBe(true);
    expect(codes.has("unknown-directive")).toBe(true);
    expect(codes.has("none-with-other-sources")).toBe(true);
    expect(codes.has("no-value-directive-with-arguments")).toBe(true);
    expect(codes.has("report-uri-without-report-to")).toBe(true);
    expect(codes.has("unsafe-inline")).toBe(true);
    expect(codes.has("unsafe-eval")).toBe(true);
    expect(codes.has("wildcard-source")).toBe(true);
    expect(codes.has("broad-scheme")).toBe(true);
  });

  it("warns about report-uri only when report-to is missing", () => {
    const codes = (csp: string) => parse(csp).warnings.map((w) => w.code);
    expect(codes("default-src 'self'; report-uri /r")).toEqual(["report-uri-without-report-to"]);
    expect(codes("default-src 'self'; report-uri /r; report-to csp")).toEqual([]);
    expect(codes("default-src 'self'; report-to csp")).toEqual([]);
  });

  it("flags bare ws: and wss: in connect-src as broad-scheme, case-insensitively", () => {
    const result = parse("default-src 'self'; connect-src 'self' WS: wss: wss://ws.example.com");
    const broad = result.warnings.filter((w) => w.code === "broad-scheme");
    expect(broad.map((w) => w.source)).toEqual(["WS:", "wss:"]);
  });

  it("classifies sources within parsed directives", () => {
    const result = parse("script-src 'self' https://cdn.example.com 'nonce-abc=='");
    const directive = result.directives[0];
    expect(directive?.sources.map((s) => s.kind)).toEqual(["keyword", "host", "nonce"]);
  });

  it("warns when neither default-src nor script-src is present", () => {
    const result = parse("img-src 'self'");
    expect(result.warnings.some((w) => w.code === "missing-default-src-or-script-src")).toBe(true);
  });

  it("does not warn about missing-default-src when script-src is set", () => {
    const result = parse("script-src 'self'");
    expect(result.warnings.some((w) => w.code === "missing-default-src-or-script-src")).toBe(false);
  });

  it("preserves directive ordering and emits errors before validation runs over them", () => {
    const result = parse("default-src 'self'; script-src 'self' 'unsafe-eval'");
    expect(result.directives[0]?.name).toBe("default-src");
    expect(result.directives[1]?.name).toBe("script-src");
    const unsafeEvalWarn = result.warnings.find((w) => w.code === "unsafe-eval");
    expect(unsafeEvalWarn?.directive).toBe("script-src");
  });

  it("propagates tokenize errors (invalid characters) into the result", () => {
    const result = parse("default-src héllo");
    expect(result.errors.some((e) => e.code === "invalid-characters")).toBe(true);
  });

  it("emits strict-dynamic-host-ignored when hosts are listed alongside 'strict-dynamic'", () => {
    const result = parse("script-src 'strict-dynamic' https://cdn.example.com 'self'");
    expect(result.warnings.some((w) => w.code === "strict-dynamic-host-ignored")).toBe(true);
  });

  it("emits missing-source-list when a fetch directive has no sources", () => {
    const result = parse("default-src");
    expect(result.errors.some((e) => e.code === "missing-source-list")).toBe(true);
  });

  it("does not flag a relative report-uri value as invalid-source-syntax", () => {
    const result = parse("default-src 'self'; script-src 'self'; report-uri /api/csp-report");
    expect(result.errors.some((e) => e.code === "invalid-source-syntax")).toBe(false);
    const reportUri = result.directives.find((d) => d.name === "report-uri");
    expect(reportUri?.sources[0]?.kind).toBe("uri");
  });

  it("flags duplicate sources within a directive", () => {
    const result = parse("default-src 'self' https://a.example.com 'self' https://a.example.com");
    const dups = result.warnings.filter((w) => w.code === "duplicate-source");
    expect(dups).toHaveLength(2);
  });

  it("warns when a directive combines unsafe-inline and unsafe-eval", () => {
    const result = parse("script-src 'self' 'unsafe-inline' 'unsafe-eval'");
    expect(result.warnings.some((w) => w.code === "unsafe-inline-with-unsafe-eval")).toBe(true);
  });

  it("accepts newer CSP3 syntax seen in the wild without false positives", () => {
    // Real-world shapes from the crawler.ninja dump.
    const result = parse(
      "default-src 'self'; script-src 'self' 'report-sha256'; fenced-frame-src https://ads.example; " +
        "require-trusted-types-for 'script'; trusted-types default dompurify goog#html 'allow-duplicates'; " +
        "webrtc 'block'; sandbox allow-scripts allow-forms",
    );
    expect(result.errors).toEqual([]);
    expect(result.warnings).toEqual([]);
  });

  it("flags hosts listed in sandbox", () => {
    const result = parse("sandbox allow-scripts https://us.plus500.com");
    expect(result.errors.map((e) => [e.code, e.source])).toEqual([
      ["invalid-source-syntax", "https://us.plus500.com"],
    ]);
  });
});
