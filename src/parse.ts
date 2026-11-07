import { classifySource } from "./source.js";
import { tokenize } from "./tokenize.js";
import { runRules } from "./rules.js";
import type { Issue, ParsedDirective, ParsedSource, ParseOptions, ParseResult } from "./types.js";

export function parse(input: string, options: ParseOptions = {}): ParseResult {
  const errors: Issue[] = [];
  const warnings: Issue[] = [];
  const directives: ParsedDirective[] = [];

  const tokenized = tokenize(input);
  errors.push(...tokenized.errors);

  for (const td of tokenized.directives) {
    const sources: ParsedSource[] = [];
    for (const t of td.valueTokens) {
      const result = classifySource(t, td.name);
      sources.push(result.source);
      errors.push(...result.errors);
      warnings.push(...result.warnings);
    }
    directives.push({ name: td.name, raw: td.raw, sources });
  }

  for (const issue of runRules(directives, {
    source: options.source ?? "header",
    disposition: options.disposition ?? "enforce",
  })) {
    if (issue.level === "error") {
      errors.push(issue);
    } else {
      warnings.push(issue);
    }
  }

  return { directives, errors, warnings };
}
