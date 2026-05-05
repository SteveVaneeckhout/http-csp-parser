import { describe, expect, it } from "vitest";
import {
  DEPRECATED_DIRECTIVES,
  DOCUMENT_DIRECTIVES,
  FETCH_DIRECTIVES,
  KNOWN_DIRECTIVES,
  KNOWN_SCHEMES,
  NAVIGATION_DIRECTIVES,
  NO_VALUE_DIRECTIVES,
  NONE_KEYWORD,
  REPORTING_DIRECTIVES,
  REQUIRES_SOURCE_LIST,
  SOURCE_KEYWORDS,
  TRUSTED_TYPES_DIRECTIVES,
} from "../src/vocabulary.js";

describe("vocabulary", () => {
  it("includes core fetch directives", () => {
    expect(FETCH_DIRECTIVES.has("default-src")).toBe(true);
    expect(FETCH_DIRECTIVES.has("script-src")).toBe(true);
    expect(FETCH_DIRECTIVES.has("style-src")).toBe(true);
    expect(FETCH_DIRECTIVES.has("img-src")).toBe(true);
    expect(FETCH_DIRECTIVES.has("connect-src")).toBe(true);
    expect(FETCH_DIRECTIVES.has("font-src")).toBe(true);
    expect(FETCH_DIRECTIVES.has("object-src")).toBe(true);
  });

  it("includes document, navigation, reporting and trusted-types groups", () => {
    expect(DOCUMENT_DIRECTIVES.has("base-uri")).toBe(true);
    expect(DOCUMENT_DIRECTIVES.has("sandbox")).toBe(true);
    expect(NAVIGATION_DIRECTIVES.has("form-action")).toBe(true);
    expect(NAVIGATION_DIRECTIVES.has("frame-ancestors")).toBe(true);
    expect(REPORTING_DIRECTIVES.has("report-to")).toBe(true);
    expect(REPORTING_DIRECTIVES.has("report-uri")).toBe(true);
    expect(TRUSTED_TYPES_DIRECTIVES.has("require-trusted-types-for")).toBe(true);
    expect(TRUSTED_TYPES_DIRECTIVES.has("trusted-types")).toBe(true);
  });

  it("flags deprecated directives", () => {
    expect(DEPRECATED_DIRECTIVES.has("report-uri")).toBe(true);
    expect(DEPRECATED_DIRECTIVES.has("plugin-types")).toBe(true);
    expect(DEPRECATED_DIRECTIVES.has("referrer")).toBe(true);
    expect(DEPRECATED_DIRECTIVES.has("prefetch-src")).toBe(true);
    expect(DEPRECATED_DIRECTIVES.has("navigate-to")).toBe(true);
    expect(DEPRECATED_DIRECTIVES.has("block-all-mixed-content")).toBe(true);
  });

  it("captures no-value directives", () => {
    expect(NO_VALUE_DIRECTIVES.has("upgrade-insecure-requests")).toBe(true);
    expect(NO_VALUE_DIRECTIVES.has("block-all-mixed-content")).toBe(true);
  });

  it("KNOWN_DIRECTIVES is a superset of all directive groups", () => {
    for (const name of [
      ...FETCH_DIRECTIVES,
      ...DOCUMENT_DIRECTIVES,
      ...NAVIGATION_DIRECTIVES,
      ...REPORTING_DIRECTIVES,
      ...TRUSTED_TYPES_DIRECTIVES,
      ...NO_VALUE_DIRECTIVES,
    ]) {
      expect(KNOWN_DIRECTIVES.has(name)).toBe(true);
    }
    expect(KNOWN_DIRECTIVES.has("plugin-types")).toBe(true);
    expect(KNOWN_DIRECTIVES.has("referrer")).toBe(true);
  });

  it("REQUIRES_SOURCE_LIST excludes no-value directives", () => {
    for (const name of NO_VALUE_DIRECTIVES) {
      expect(REQUIRES_SOURCE_LIST.has(name)).toBe(false);
    }
    expect(REQUIRES_SOURCE_LIST.has("default-src")).toBe(true);
    expect(REQUIRES_SOURCE_LIST.has("base-uri")).toBe(true);
    expect(REQUIRES_SOURCE_LIST.has("form-action")).toBe(true);
    expect(REQUIRES_SOURCE_LIST.has("frame-ancestors")).toBe(true);
  });

  it("source keywords use canonical lowercase form with quotes", () => {
    expect(SOURCE_KEYWORDS.has("'self'")).toBe(true);
    expect(SOURCE_KEYWORDS.has("'unsafe-inline'")).toBe(true);
    expect(SOURCE_KEYWORDS.has("'unsafe-eval'")).toBe(true);
    expect(SOURCE_KEYWORDS.has("'strict-dynamic'")).toBe(true);
    expect(SOURCE_KEYWORDS.has("'wasm-unsafe-eval'")).toBe(true);
    expect(SOURCE_KEYWORDS.has("'unsafe-hashes'")).toBe(true);
    expect(SOURCE_KEYWORDS.has("'inline-speculation-rules'")).toBe(true);
    expect(SOURCE_KEYWORDS.has("'report-sample'")).toBe(true);
    expect(NONE_KEYWORD).toBe("'none'");
  });

  it("includes common schemes", () => {
    expect(KNOWN_SCHEMES.has("http")).toBe(true);
    expect(KNOWN_SCHEMES.has("https")).toBe(true);
    expect(KNOWN_SCHEMES.has("data")).toBe(true);
    expect(KNOWN_SCHEMES.has("blob")).toBe(true);
    expect(KNOWN_SCHEMES.has("ws")).toBe(true);
    expect(KNOWN_SCHEMES.has("wss")).toBe(true);
  });
});
