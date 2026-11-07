export const FETCH_DIRECTIVES: ReadonlySet<string> = new Set([
  "child-src",
  "connect-src",
  "default-src",
  "font-src",
  "frame-src",
  "img-src",
  "manifest-src",
  "media-src",
  "object-src",
  "prefetch-src",
  "script-src",
  "script-src-elem",
  "script-src-attr",
  "style-src",
  "style-src-elem",
  "style-src-attr",
  "worker-src",
]);

export const DOCUMENT_DIRECTIVES: ReadonlySet<string> = new Set(["base-uri", "sandbox"]);

export const NAVIGATION_DIRECTIVES: ReadonlySet<string> = new Set([
  "form-action",
  "frame-ancestors",
  "navigate-to",
]);

export const REPORTING_DIRECTIVES: ReadonlySet<string> = new Set(["report-to", "report-uri"]);

export const TRUSTED_TYPES_DIRECTIVES: ReadonlySet<string> = new Set([
  "require-trusted-types-for",
  "trusted-types",
]);

export const NO_VALUE_DIRECTIVES: ReadonlySet<string> = new Set([
  "block-all-mixed-content",
  "upgrade-insecure-requests",
]);

export const DEPRECATED_DIRECTIVES: ReadonlySet<string> = new Set([
  "block-all-mixed-content",
  "navigate-to",
  "plugin-types",
  "prefetch-src",
  "referrer",
]);
// "report-uri" is deprecated too, but it is the only reporting mechanism in older browsers
// (e.g. Firefox before 149), so it is handled by ruleReportUriWithoutReportTo instead.

export const KNOWN_DIRECTIVES: ReadonlySet<string> = FETCH_DIRECTIVES.union(DOCUMENT_DIRECTIVES)
  .union(NAVIGATION_DIRECTIVES)
  .union(REPORTING_DIRECTIVES)
  .union(TRUSTED_TYPES_DIRECTIVES)
  .union(NO_VALUE_DIRECTIVES)
  .union(new Set(["plugin-types", "referrer"]));

export const REQUIRES_SOURCE_LIST: ReadonlySet<string> = new Set([
  ...FETCH_DIRECTIVES,
  "base-uri",
  "form-action",
  "frame-ancestors",
  "navigate-to",
]);

export const SOURCE_KEYWORDS: ReadonlySet<string> = new Set([
  "'self'",
  "'unsafe-inline'",
  "'unsafe-eval'",
  "'unsafe-hashes'",
  "'strict-dynamic'",
  "'wasm-unsafe-eval'",
  "'inline-speculation-rules'",
  "'report-sample'",
  "'unsafe-allow-redirects'",
]);

export const NONE_KEYWORD = "'none'";

export const KNOWN_SCHEMES: ReadonlySet<string> = new Set([
  "blob",
  "data",
  "file",
  "filesystem",
  "ftp",
  "http",
  "https",
  "mediastream",
  "ws",
  "wss",
]);
