export const FETCH_DIRECTIVES = new Set([
    "child-src",
    "connect-src",
    "default-src",
    "fenced-frame-src",
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
export const DOCUMENT_DIRECTIVES = new Set(["base-uri", "sandbox"]);
export const NAVIGATION_DIRECTIVES = new Set([
    "form-action",
    "frame-ancestors",
    "navigate-to",
]);
export const REPORTING_DIRECTIVES = new Set(["report-to", "report-uri"]);
export const TRUSTED_TYPES_DIRECTIVES = new Set([
    "require-trusted-types-for",
    "trusted-types",
]);
// Directives whose single value is 'allow' or 'block'.
export const OTHER_DIRECTIVES = new Set(["webrtc"]);
export const NO_VALUE_DIRECTIVES = new Set([
    "block-all-mixed-content",
    "upgrade-insecure-requests",
]);
export const DEPRECATED_DIRECTIVES = new Set([
    "block-all-mixed-content",
    "navigate-to",
    "plugin-types",
    "prefetch-src",
    "referrer",
]);
// "report-uri" is deprecated too, but it is the only reporting mechanism in older browsers
// (e.g. Firefox before 149), so it is handled by ruleReportUriWithoutReportTo instead.
export const KNOWN_DIRECTIVES = FETCH_DIRECTIVES.union(DOCUMENT_DIRECTIVES)
    .union(NAVIGATION_DIRECTIVES)
    .union(REPORTING_DIRECTIVES)
    .union(TRUSTED_TYPES_DIRECTIVES)
    .union(OTHER_DIRECTIVES)
    .union(NO_VALUE_DIRECTIVES)
    .union(new Set(["plugin-types", "referrer"]));
export const REQUIRES_SOURCE_LIST = new Set([
    ...FETCH_DIRECTIVES,
    "base-uri",
    "form-action",
    "frame-ancestors",
    "navigate-to",
]);
export const SOURCE_KEYWORDS = new Set([
    "'self'",
    "'unsafe-inline'",
    "'unsafe-eval'",
    "'unsafe-hashes'",
    "'strict-dynamic'",
    "'wasm-unsafe-eval'",
    "'inline-speculation-rules'",
    "'report-sample'",
    "'report-sha256'",
    "'report-sha384'",
    "'report-sha512'",
    "'trusted-types-eval'",
    "'unsafe-webtransport-hashes'",
    "'unsafe-allow-redirects'",
]);
export const NONE_KEYWORD = "'none'";
// Bare schemes that allow any host: "https:" means every https origin.
export const BROAD_SCHEMES = new Set(["http", "https", "ws", "wss"]);
export const KNOWN_SCHEMES = new Set([
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
// Sandbox flags from the HTML spec, plus allow-storage-access-by-user-activation from the
// Storage Access API. Matched ASCII case-insensitively; unknown flags are ignored by browsers.
export const SANDBOX_FLAGS = new Set([
    "allow-downloads",
    "allow-forms",
    "allow-modals",
    "allow-orientation-lock",
    "allow-pointer-lock",
    "allow-popups",
    "allow-popups-to-escape-sandbox",
    "allow-presentation",
    "allow-same-origin",
    "allow-scripts",
    "allow-storage-access-by-user-activation",
    "allow-top-navigation",
    "allow-top-navigation-by-user-activation",
    "allow-top-navigation-to-custom-protocols",
]);
// Value keywords for directives that don't take a source list.
export const DIRECTIVE_VALUE_KEYWORDS = new Map([
    ["require-trusted-types-for", new Set(["'script'"])],
    ["trusted-types", new Set(["'allow-duplicates'"])],
    ["webrtc", new Set(["'allow'", "'block'"])],
]);
