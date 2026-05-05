import type { Issue } from "./types.js";

export interface TokenizedDirective {
  readonly name: string;
  readonly raw: string;
  readonly valueTokens: readonly string[];
}

export interface TokenizeResult {
  readonly directives: readonly TokenizedDirective[];
  readonly errors: readonly Issue[];
}

const ASCII_PRINTABLE_RE = /^[\t\x20-\x7e]*$/;
const WSP_TRIM_RE = /^[ \t]+|[ \t]+$/g;
const WSP_SPLIT_RE = /[ \t]+/;

export function tokenize(input: string): TokenizeResult {
  const errors: Issue[] = [];
  const directives: TokenizedDirective[] = [];

  if (input.trim() === "") {
    errors.push({
      code: "empty-input",
      level: "error",
      message: "CSP header is empty.",
    });
    return { directives, errors };
  }

  if (!ASCII_PRINTABLE_RE.test(input)) {
    errors.push({
      code: "invalid-characters",
      level: "error",
      message: "CSP header contains non-ASCII or control characters.",
    });
  }

  const segments = input.split(";");
  const lastIndex = segments.length - 1;
  for (let i = 0; i < segments.length; i++) {
    const segment = segments[i]!;
    const trimmed = segment.replace(WSP_TRIM_RE, "");
    if (trimmed === "") {
      if (i !== lastIndex) {
        errors.push({
          code: "empty-directive",
          level: "error",
          message: "Empty directive between semicolons.",
        });
      }
      continue;
    }
    const parts = trimmed.split(WSP_SPLIT_RE);
    const rawName = parts[0]!;
    directives.push({
      name: rawName.toLowerCase(),
      raw: rawName,
      valueTokens: parts.slice(1),
    });
  }

  return { directives, errors };
}
