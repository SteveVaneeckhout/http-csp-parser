import { describe, expect, it } from "vitest";
import { tokenize } from "../src/tokenize.js";

describe("tokenize", () => {
  it("emits empty-input for an empty string", () => {
    const result = tokenize("");
    expect(result.directives).toEqual([]);
    expect(result.errors).toHaveLength(1);
    expect(result.errors[0]?.code).toBe("empty-input");
    expect(result.errors[0]?.level).toBe("error");
  });

  it("emits empty-input for whitespace-only input", () => {
    const result = tokenize("   \t  ");
    expect(result.directives).toEqual([]);
    expect(result.errors).toHaveLength(1);
    expect(result.errors[0]?.code).toBe("empty-input");
  });

  it("parses a single directive with sources", () => {
    const result = tokenize("default-src 'self'");
    expect(result.errors).toEqual([]);
    expect(result.directives).toHaveLength(1);
    expect(result.directives[0]).toEqual({
      name: "default-src",
      raw: "default-src",
      valueTokens: ["'self'"],
    });
  });

  it("preserves the directive name's original casing in raw", () => {
    const result = tokenize("Default-Src 'self'");
    expect(result.directives[0]?.name).toBe("default-src");
    expect(result.directives[0]?.raw).toBe("Default-Src");
  });

  it("parses multiple directives separated by semicolons", () => {
    const result = tokenize("default-src 'self'; script-src 'self' https://cdn.example.com");
    expect(result.errors).toEqual([]);
    expect(result.directives).toHaveLength(2);
    expect(result.directives[0]?.name).toBe("default-src");
    expect(result.directives[1]?.name).toBe("script-src");
    expect(result.directives[1]?.valueTokens).toEqual(["'self'", "https://cdn.example.com"]);
  });

  it("treats a single trailing semicolon as not an empty directive", () => {
    const result = tokenize("default-src 'self';");
    expect(result.errors).toEqual([]);
    expect(result.directives).toHaveLength(1);
  });

  it("emits empty-directive for repeated semicolons in the middle", () => {
    const result = tokenize("default-src 'self';;script-src 'self'");
    expect(result.errors).toHaveLength(1);
    expect(result.errors[0]?.code).toBe("empty-directive");
    expect(result.directives).toHaveLength(2);
  });

  it("emits empty-directive once per empty middle segment", () => {
    const result = tokenize(";;a;;");
    const emptyDirectiveErrors = result.errors.filter((e) => e.code === "empty-directive");
    expect(emptyDirectiveErrors).toHaveLength(3);
    expect(result.directives).toHaveLength(1);
    expect(result.directives[0]?.name).toBe("a");
  });

  it("trims leading and trailing whitespace around directive segments", () => {
    const result = tokenize("   default-src   'self'   ;   img-src   *  ");
    expect(result.errors).toEqual([]);
    expect(result.directives).toEqual([
      { name: "default-src", raw: "default-src", valueTokens: ["'self'"] },
      { name: "img-src", raw: "img-src", valueTokens: ["*"] },
    ]);
  });

  it("treats tabs as whitespace", () => {
    const result = tokenize("default-src\t'self'\t'unsafe-inline'");
    expect(result.errors).toEqual([]);
    expect(result.directives[0]?.valueTokens).toEqual(["'self'", "'unsafe-inline'"]);
  });

  it("splits on every ASCII whitespace character (LF, FF, CR), not only space and tab", () => {
    // Real-world policy from the crawler.ninja dump, served as a folded header.
    const result = tokenize(
      "default-src 'self';\n    frame-ancestors 'self' www.youtube.com;\r\n\tobject-src\f'none'",
    );
    expect(result.directives).toEqual([
      { name: "default-src", raw: "default-src", valueTokens: ["'self'"] },
      {
        name: "frame-ancestors",
        raw: "frame-ancestors",
        valueTokens: ["'self'", "www.youtube.com"],
      },
      { name: "object-src", raw: "object-src", valueTokens: ["'none'"] },
    ]);
  });

  it("emits one invalid-characters error that names the line break", () => {
    const result = tokenize("default-src 'self';\n  img-src *");
    expect(result.errors).toHaveLength(1);
    expect(result.errors[0]?.code).toBe("invalid-characters");
    expect(result.errors[0]?.message).toContain("line break");
  });

  it("treats input that is only line breaks as empty", () => {
    const result = tokenize("\r\n\n");
    expect(result.errors.map((e) => e.code)).toEqual(["empty-input"]);
  });

  it("emits invalid-characters when input contains non-ASCII characters", () => {
    const result = tokenize("default-src héllo.com");
    const invalid = result.errors.filter((e) => e.code === "invalid-characters");
    expect(invalid).toHaveLength(1);
    expect(invalid[0]?.level).toBe("error");
  });

  it("emits invalid-characters for control characters", () => {
    const result = tokenize("default-src\x01'self'");
    const invalid = result.errors.filter((e) => e.code === "invalid-characters");
    expect(invalid).toHaveLength(1);
  });

  it("emits invalid-characters for DEL", () => {
    const result = tokenize("default-src 'self'\x7f");
    const invalid = result.errors.filter((e) => e.code === "invalid-characters");
    expect(invalid).toHaveLength(1);
  });

  it("does not emit invalid-characters for an all-ASCII input", () => {
    const result = tokenize("default-src 'self'");
    expect(result.errors.filter((e) => e.code === "invalid-characters")).toHaveLength(0);
  });

  it("yields directives even when invalid-characters is present", () => {
    const result = tokenize("default-src héllo.com");
    expect(result.directives).toHaveLength(1);
    expect(result.directives[0]?.name).toBe("default-src");
  });
});
