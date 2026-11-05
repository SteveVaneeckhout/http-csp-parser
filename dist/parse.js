import { classifySource } from "./source.js";
import { tokenize } from "./tokenize.js";
import { runRules } from "./rules.js";
export function parse(input) {
    const errors = [];
    const warnings = [];
    const directives = [];
    const tokenized = tokenize(input);
    errors.push(...tokenized.errors);
    for (const td of tokenized.directives) {
        const sources = [];
        for (const t of td.valueTokens) {
            const result = classifySource(t, td.name);
            sources.push(result.source);
            errors.push(...result.errors);
            warnings.push(...result.warnings);
        }
        directives.push({ name: td.name, raw: td.raw, sources });
    }
    for (const issue of runRules(directives)) {
        if (issue.level === "error") {
            errors.push(issue);
        }
        else {
            warnings.push(issue);
        }
    }
    return { directives, errors, warnings };
}
