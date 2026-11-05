import { hash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { classifySource } from "../src/source.js";

describe("classifySource – hash digest length", () => {
  it.each(["sha256", "sha384", "sha512"] as const)(
    "accepts a real %s digest in base64 without warnings",
    (algo) => {
      const digest = hash(algo, "alert(1)", "base64");
      const r = classifySource(`'${algo}-${digest}'`, "script-src");
      expect(r.errors).toEqual([]);
      expect(r.warnings).toEqual([]);
    },
  );

  it("accepts a base64url digest without padding", () => {
    const digest = hash("sha256", "alert(1)", "base64url");
    const r = classifySource(`'sha256-${digest}'`, "script-src");
    expect(r.warnings).toEqual([]);
  });

  it("warns when the digest length does not match the algorithm", () => {
    const digest = hash("sha256", "alert(1)", "base64");
    const r = classifySource(`'sha512-${digest}'`, "script-src");
    expect(r.errors).toEqual([]);
    expect(r.warnings).toHaveLength(1);
    expect(r.warnings[0]?.code).toBe("hash-length-mismatch");
    expect(r.warnings[0]?.message).toContain("decodes to 32 bytes");
  });

  it("warns when the digest is not decodable base64", () => {
    const r = classifySource("'sha256-A'", "script-src");
    expect(r.errors).toEqual([]);
    expect(r.warnings[0]?.code).toBe("hash-length-mismatch");
    expect(r.warnings[0]?.message).toContain("not valid base64");
  });
});

describe("classifySource", () => {
  it("classifies bare '*' as wildcard host with a warning", () => {
    const r = classifySource("*", "default-src");
    expect(r.source.kind).toBe("host");
    expect(r.source.host).toBe("*");
    expect(r.errors).toEqual([]);
    expect(r.warnings).toHaveLength(1);
    expect(r.warnings[0]?.code).toBe("wildcard-source");
  });

  it("classifies 'none' (case-insensitive) as none kind", () => {
    const r = classifySource("'none'", "default-src");
    expect(r.source.kind).toBe("none");
    expect(r.source.keyword).toBe("'none'");
    const upper = classifySource("'NONE'", "default-src");
    expect(upper.source.kind).toBe("none");
  });

  it("classifies 'self' as a keyword", () => {
    const r = classifySource("'self'", "default-src");
    expect(r.source.kind).toBe("keyword");
    expect(r.source.keyword).toBe("'self'");
    expect(r.errors).toEqual([]);
    expect(r.warnings).toEqual([]);
  });

  it("emits unsafe-inline warning for 'unsafe-inline'", () => {
    const r = classifySource("'unsafe-inline'", "script-src");
    expect(r.source.kind).toBe("keyword");
    expect(r.warnings).toHaveLength(1);
    expect(r.warnings[0]?.code).toBe("unsafe-inline");
  });

  it("emits unsafe-eval warning for 'unsafe-eval'", () => {
    const r = classifySource("'unsafe-eval'", "script-src");
    expect(r.source.kind).toBe("keyword");
    expect(r.warnings).toHaveLength(1);
    expect(r.warnings[0]?.code).toBe("unsafe-eval");
  });

  it("emits no extra warning for non-unsafe known keywords", () => {
    const r = classifySource("'strict-dynamic'", "script-src");
    expect(r.source.kind).toBe("keyword");
    expect(r.warnings).toEqual([]);
  });

  it("warns on unknown quoted keyword", () => {
    const r = classifySource("'mystery'", "script-src");
    expect(r.source.kind).toBe("unknown");
    expect(r.warnings).toHaveLength(1);
    expect(r.warnings[0]?.code).toBe("unknown-source-keyword");
  });

  it("classifies a valid nonce", () => {
    const r = classifySource("'nonce-abc123=='", "script-src");
    expect(r.source.kind).toBe("nonce");
    expect(r.source.value).toBe("abc123==");
    expect(r.errors).toEqual([]);
  });

  it("accepts base64url alphabet for nonces", () => {
    const r = classifySource("'nonce-abc-_xyz'", "script-src");
    expect(r.source.kind).toBe("nonce");
    expect(r.source.value).toBe("abc-_xyz");
  });

  it("emits invalid-nonce when payload is malformed", () => {
    const r = classifySource("'nonce-!!!'", "script-src");
    expect(r.source.kind).toBe("nonce");
    expect(r.errors).toHaveLength(1);
    expect(r.errors[0]?.code).toBe("invalid-nonce");
  });

  it("emits invalid-nonce when nonce is empty", () => {
    const r = classifySource("'nonce-'", "script-src");
    expect(r.source.kind).toBe("nonce");
    expect(r.errors[0]?.code).toBe("invalid-nonce");
  });

  it("classifies sha256, sha384, and sha512 hashes", () => {
    for (const algo of ["sha256", "sha384", "sha512"] as const) {
      const r = classifySource(`'${algo}-abc123=='`, "script-src");
      expect(r.source.kind).toBe("hash");
      expect(r.source.algorithm).toBe(algo);
      expect(r.source.value).toBe("abc123==");
      expect(r.errors).toEqual([]);
    }
  });

  it("emits invalid-hash for malformed hash payload", () => {
    const r = classifySource("'sha256-!!!'", "script-src");
    expect(r.source.kind).toBe("hash");
    expect(r.errors).toHaveLength(1);
    expect(r.errors[0]?.code).toBe("invalid-hash");
  });

  it("classifies a scheme-only source", () => {
    const r = classifySource("https:", "img-src");
    expect(r.source.kind).toBe("scheme");
    expect(r.source.scheme).toBe("https");
    expect(r.errors).toEqual([]);
    expect(r.warnings).toEqual([]);
  });

  it("normalizes scheme casing", () => {
    const r = classifySource("HTTPS:", "img-src");
    expect(r.source.scheme).toBe("https");
  });

  it("classifies a simple host", () => {
    const r = classifySource("example.com", "default-src");
    expect(r.source.kind).toBe("host");
    expect(r.source.host).toBe("example.com");
    expect(r.source.scheme).toBeUndefined();
    expect(r.source.port).toBeUndefined();
    expect(r.source.path).toBeUndefined();
  });

  it("classifies a host with scheme, port, and path", () => {
    const r = classifySource("https://cdn.example.com:8443/static/app.js", "script-src");
    expect(r.source.kind).toBe("host");
    expect(r.source.scheme).toBe("https");
    expect(r.source.host).toBe("cdn.example.com");
    expect(r.source.port).toBe("8443");
    expect(r.source.path).toBe("/static/app.js");
  });

  it("classifies a host with wildcard subdomain prefix", () => {
    const r = classifySource("*.example.com", "default-src");
    expect(r.source.kind).toBe("host");
    expect(r.source.host).toBe("*.example.com");
  });

  it("classifies a host with wildcard port", () => {
    const r = classifySource("example.com:*", "default-src");
    expect(r.source.kind).toBe("host");
    expect(r.source.port).toBe("*");
  });

  it("emits invalid-source-syntax for garbage tokens", () => {
    const r = classifySource("@@@!!", "default-src");
    expect(r.source.kind).toBe("unknown");
    expect(r.errors).toHaveLength(1);
    expect(r.errors[0]?.code).toBe("invalid-source-syntax");
  });

  it("classifies report-uri values as kind 'uri' without errors", () => {
    const relative = classifySource("/api/csp-report", "report-uri");
    expect(relative.source.kind).toBe("uri");
    expect(relative.errors).toEqual([]);
    expect(relative.warnings).toEqual([]);

    const absolute = classifySource("https://reports.example.com/csp", "report-uri");
    expect(absolute.source.kind).toBe("uri");
    expect(absolute.errors).toEqual([]);
  });

  it("classifies a valid report-to group name as kind 'token'", () => {
    const r = classifySource("default-endpoint", "report-to");
    expect(r.source.kind).toBe("token");
    expect(r.errors).toEqual([]);
  });

  it("emits invalid-source-syntax for a malformed report-to group name", () => {
    const r = classifySource("foo!bar", "report-to");
    expect(r.source.kind).toBe("unknown");
    expect(r.errors).toHaveLength(1);
    expect(r.errors[0]?.code).toBe("invalid-source-syntax");
  });
});
