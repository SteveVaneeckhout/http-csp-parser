# http-csp-parser

> Parse and analyze HTTP `Content-Security-Policy` headers — single call, ESM, zero runtime dependencies.

`http-csp-parser` takes a raw CSP header string and returns the parsed directives plus arrays of errors and warnings. It does not fetch URLs, enforce policies, or modify your code — it is purely a static analyzer suited for CI checks, devtools panels, and security review scripts.
Made with Claude.ai

## Install

```bash
npm install http-csp-parser
```

Requires Node.js **26.13** or newer (ESM-only).

## Quick start

```ts
import { parse } from "http-csp-parser";

const { directives, errors, warnings } = parse(
  "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.example.com",
);

console.log(directives);
// [
//   { name: "default-src", raw: "default-src", sources: [{ kind: "keyword", keyword: "'self'", raw: "'self'" }] },
//   { name: "script-src",  raw: "script-src",  sources: [/* 'self', 'unsafe-inline', host */] },
// ]

console.log(warnings.map((w) => w.code));
// [ "unsafe-inline" ]
```

## API

### `parse(input: string): ParseResult`

Parses, classifies, and analyzes a CSP header in a single pass.

```ts
interface ParseResult {
  readonly directives: readonly ParsedDirective[];
  readonly errors: readonly Issue[];
  readonly warnings: readonly Issue[];
}

interface ParsedDirective {
  readonly name: string; // lowercased
  readonly raw: string; // original casing
  readonly sources: readonly ParsedSource[];
}

interface ParsedSource {
  readonly raw: string;
  readonly kind:
    | "keyword"
    | "scheme"
    | "host"
    | "nonce"
    | "hash"
    | "none"
    | "uri"
    | "token"
    | "unknown";
  readonly keyword?: string; // when kind === "keyword" or "none"
  readonly scheme?: string; // when kind === "scheme" or "host" with scheme prefix
  readonly host?: string; // when kind === "host"
  readonly port?: string; // when kind === "host"
  readonly path?: string; // when kind === "host"
  readonly algorithm?: "sha256" | "sha384" | "sha512"; // when kind === "hash"
  readonly value?: string; // base64 payload for nonce/hash
}

interface Issue {
  readonly code: IssueCode;
  readonly level: "error" | "warning";
  readonly message: string;
  readonly directive?: string; // present for directive-scoped issues
  readonly source?: string; // present for source-scoped issues
}
```

`errors` indicate something the policy specifies that browsers will reject or that the spec does not allow. `warnings` indicate something the policy will accept but that weakens its security guarantees.

## Issue reference

### Errors

| Code                                | Trigger                                                                                  |
| ----------------------------------- | ---------------------------------------------------------------------------------------- |
| `empty-input`                       | The header is empty or whitespace-only.                                                  |
| `empty-directive`                   | A `;`-separated segment contains no tokens.                                              |
| `duplicate-directive`               | The same directive name appears more than once.                                          |
| `unknown-directive`                 | The directive name is not part of CSP3 or its recognized predecessors.                   |
| `invalid-characters`                | The header contains non-ASCII or control characters.                                     |
| `invalid-source-syntax`             | A source token does not match any valid grammar production.                              |
| `invalid-nonce`                     | A `'nonce-…'` source has a malformed payload.                                            |
| `invalid-hash`                      | A `'sha256-…'` / `'sha384-…'` / `'sha512-…'` source has a malformed payload.             |
| `none-with-other-sources`           | `'none'` appears alongside other sources.                                                |
| `no-value-directive-with-arguments` | A directive that takes no values (e.g. `upgrade-insecure-requests`) was given arguments. |
| `missing-source-list`               | A directive that requires sources was given none.                                        |

> **Note**: `report-uri` accepts URI references (including relative paths) and `report-to` accepts a single group name token. Their values are classified as `kind: "uri"` and `kind: "token"` respectively, and source-list rules do not apply to them.

### Warnings

| Code                                | Trigger                                                                                                                                                                                   |
| ----------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `unsafe-inline`                     | The keyword `'unsafe-inline'` is present.                                                                                                                                                 |
| `unsafe-eval`                       | The keyword `'unsafe-eval'` is present.                                                                                                                                                   |
| `unsafe-inline-with-unsafe-eval`    | A directive contains both `'unsafe-inline'` and `'unsafe-eval'`, which together effectively nullify XSS protection.                                                                       |
| `wildcard-source`                   | A bare `*` source is used.                                                                                                                                                                |
| `duplicate-source`                  | The same source value appears more than once within a single directive (case-insensitive `raw` match).                                                                                    |
| `deprecated-directive`              | The directive is deprecated (e.g. `plugin-types`, `referrer`, `prefetch-src`, `navigate-to`, `block-all-mixed-content`).                                                                  |
| `report-uri-without-report-to`      | `report-uri` is used without `report-to`. Add `report-to` (plus a `Reporting-Endpoints` header) and keep `report-uri` as a fallback for older browsers; no warning when both are present. |
| `missing-default-src-or-script-src` | The policy contains neither `default-src` nor `script-src`.                                                                                                                               |
| `strict-dynamic-host-ignored`       | A host or scheme source is listed alongside `'strict-dynamic'`, where browsers will ignore it.                                                                                            |
| `broad-scheme`                      | A fetch directive includes the bare `http:` or `https:` scheme as a source.                                                                                                               |
| `unknown-source-keyword`            | A `'…'`-quoted token is not a recognized CSP source keyword.                                                                                                                              |
| `hash-length-mismatch`              | A hash source's digest does not decode to the size of its algorithm (32/48/64 bytes for sha256/384/512), so it can never match.                                                           |

## Examples

A strict, well-formed policy:

```ts
parse("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:");
// → no errors, no warnings
```

A policy with multiple issues:

```ts
const result = parse(
  "default-src 'self' 'unsafe-inline'; default-src 'self'; widget-src *; script-src 'unsafe-eval' https:; upgrade-insecure-requests https:",
);
// errors:   duplicate-directive, unknown-directive, no-value-directive-with-arguments
// warnings: unsafe-inline, wildcard-source, unsafe-eval, broad-scheme, missing-default-src-or-script-src
```

## What the parser does _not_ do

- It does **not** fetch URLs or resolve relative references.
- It does **not** enforce a CSP — it analyzes a header string only.
- It does **not** validate that hosts or hashes correspond to actual resources.
- The directive vocabulary is hand-curated in `src/vocabulary.ts`. Future CSP additions may require a vocabulary update.

## Development

```bash
npm run typecheck      # tsc --noEmit
npm run test           # vitest run
npm run test:coverage  # vitest run --coverage (100% required)
npm run build          # tsc
npm run fmt            # oxfmt
```

## License

MIT
