export type IssueLevel = "error" | "warning";

export type IssueCode =
  | "empty-input"
  | "empty-directive"
  | "duplicate-directive"
  | "duplicate-source"
  | "unknown-directive"
  | "invalid-characters"
  | "invalid-source-syntax"
  | "invalid-nonce"
  | "invalid-hash"
  | "hash-length-mismatch"
  | "none-with-other-sources"
  | "no-value-directive-with-arguments"
  | "missing-source-list"
  | "unsafe-inline"
  | "unsafe-eval"
  | "unsafe-inline-with-unsafe-eval"
  | "wildcard-source"
  | "deprecated-directive"
  | "report-uri-without-report-to"
  | "missing-default-src-or-script-src"
  | "strict-dynamic-host-ignored"
  | "broad-scheme"
  | "unknown-source-keyword"
  | "directive-ignored"
  | "policy-ignored";

export type SourceKind =
  | "keyword"
  | "scheme"
  | "host"
  | "nonce"
  | "hash"
  | "none"
  | "uri"
  | "token"
  | "unknown";

/** Where the policy came from, as in the CSP3 policy's "source". */
export type PolicySource = "header" | "meta";

/** Whether the policy is enforced or report-only, as in the CSP3 policy's "disposition". */
export type PolicyDisposition = "enforce" | "report";

export interface ParseOptions {
  /** "header" (default) or "meta" for a `<meta http-equiv="Content-Security-Policy">` policy. */
  readonly source?: PolicySource;
  /** "enforce" (default) or "report" for a `Content-Security-Policy-Report-Only` header. */
  readonly disposition?: PolicyDisposition;
}

export type HashAlgorithm = "sha256" | "sha384" | "sha512";

export interface Issue {
  readonly code: IssueCode;
  readonly level: IssueLevel;
  readonly message: string;
  readonly directive?: string;
  readonly source?: string;
}

export interface ParsedSource {
  readonly raw: string;
  readonly kind: SourceKind;
  readonly keyword?: string;
  readonly scheme?: string;
  readonly host?: string;
  readonly port?: string;
  readonly path?: string;
  readonly algorithm?: HashAlgorithm;
  readonly value?: string;
}

export interface ParsedDirective {
  readonly name: string;
  readonly raw: string;
  readonly sources: readonly ParsedSource[];
}

export interface ParseResult {
  readonly directives: readonly ParsedDirective[];
  readonly errors: readonly Issue[];
  readonly warnings: readonly Issue[];
}
