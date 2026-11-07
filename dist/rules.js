import { BROAD_SCHEMES, DEPRECATED_DIRECTIVES, FETCH_DIRECTIVES, KNOWN_DIRECTIVES, META_IGNORED_DIRECTIVES, NO_VALUE_DIRECTIVES, REPORT_ONLY_IGNORED_DIRECTIVES, REQUIRES_SOURCE_LIST, } from "./vocabulary.js";
export const DEFAULT_CONTEXT = { source: "header", disposition: "enforce" };
export const ruleDuplicateDirective = (directives) => {
    const issues = [];
    const seen = new Set();
    for (const d of directives) {
        if (seen.has(d.name)) {
            issues.push({
                code: "duplicate-directive",
                level: "error",
                message: `Directive "${d.name}" appears more than once; later occurrences are ignored.`,
                directive: d.name,
            });
        }
        else {
            seen.add(d.name);
        }
    }
    return issues;
};
export const ruleDuplicateSource = (directives) => {
    const issues = [];
    for (const d of directives) {
        const seen = new Set();
        const reported = new Set();
        for (const s of d.sources) {
            const key = s.raw.toLowerCase();
            if (seen.has(key)) {
                if (!reported.has(key)) {
                    reported.add(key);
                    issues.push({
                        code: "duplicate-source",
                        level: "warning",
                        message: `Source "${s.raw}" is listed more than once in "${d.name}".`,
                        directive: d.name,
                        source: s.raw,
                    });
                }
            }
            else {
                seen.add(key);
            }
        }
    }
    return issues;
};
export const ruleUnknownDirective = (directives) => {
    const issues = [];
    for (const d of directives) {
        if (!KNOWN_DIRECTIVES.has(d.name)) {
            issues.push({
                code: "unknown-directive",
                level: "error",
                message: `Unknown directive "${d.name}".`,
                directive: d.name,
            });
        }
    }
    return issues;
};
export const ruleNoneWithOtherSources = (directives) => {
    const issues = [];
    for (const d of directives) {
        const hasNone = d.sources.some((s) => s.kind === "none");
        if (hasNone && d.sources.length > 1) {
            issues.push({
                code: "none-with-other-sources",
                level: "error",
                message: `"'none'" must be the only source in "${d.name}".`,
                directive: d.name,
            });
        }
    }
    return issues;
};
export const ruleNoValueDirectiveWithArguments = (directives) => {
    const issues = [];
    for (const d of directives) {
        if (NO_VALUE_DIRECTIVES.has(d.name) && d.sources.length > 0) {
            issues.push({
                code: "no-value-directive-with-arguments",
                level: "error",
                message: `Directive "${d.name}" does not accept any arguments.`,
                directive: d.name,
            });
        }
    }
    return issues;
};
export const ruleMissingSourceList = (directives) => {
    const issues = [];
    for (const d of directives) {
        if (REQUIRES_SOURCE_LIST.has(d.name) && d.sources.length === 0) {
            issues.push({
                code: "missing-source-list",
                level: "error",
                message: `Directive "${d.name}" requires at least one source value.`,
                directive: d.name,
            });
        }
    }
    return issues;
};
export const ruleDeprecatedDirective = (directives) => {
    const issues = [];
    for (const d of directives) {
        if (DEPRECATED_DIRECTIVES.has(d.name)) {
            issues.push({
                code: "deprecated-directive",
                level: "warning",
                message: `Directive "${d.name}" is deprecated.`,
                directive: d.name,
            });
        }
    }
    return issues;
};
export const ruleReportUriWithoutReportTo = (directives, context = DEFAULT_CONTEXT) => {
    // In a meta policy report-uri is ignored altogether; ruleIgnoredDirective reports that.
    if (context.source === "meta") {
        return [];
    }
    const hasReportUri = directives.some((d) => d.name === "report-uri");
    const hasReportTo = directives.some((d) => d.name === "report-to");
    if (!hasReportUri || hasReportTo) {
        return [];
    }
    return [
        {
            code: "report-uri-without-report-to",
            level: "warning",
            message: 'Directive "report-uri" is deprecated; add "report-to" (with a Reporting-Endpoints header) and keep "report-uri" as a fallback for older browsers.',
            directive: "report-uri",
        },
    ];
};
export const ruleMissingDefaultOrScriptSrc = (directives) => {
    if (directives.length === 0) {
        return [];
    }
    const hasDefault = directives.some((d) => d.name === "default-src");
    const hasScript = directives.some((d) => d.name === "script-src");
    if (hasDefault || hasScript) {
        return [];
    }
    return [
        {
            code: "missing-default-src-or-script-src",
            level: "warning",
            message: "Policy has neither 'default-src' nor 'script-src'; scripts may load from any origin.",
        },
    ];
};
export const ruleStrictDynamicHostIgnored = (directives) => {
    const issues = [];
    for (const d of directives) {
        const hasStrictDynamic = d.sources.some((s) => s.kind === "keyword" && s.keyword === "'strict-dynamic'");
        if (!hasStrictDynamic) {
            continue;
        }
        for (const s of d.sources) {
            if (s.kind === "host" || s.kind === "scheme") {
                issues.push({
                    code: "strict-dynamic-host-ignored",
                    level: "warning",
                    message: `"'strict-dynamic'" causes user agents to ignore host/scheme source "${s.raw}" in "${d.name}".`,
                    directive: d.name,
                    source: s.raw,
                });
            }
        }
    }
    return issues;
};
export const ruleUnsafeInlineWithUnsafeEval = (directives) => {
    const issues = [];
    for (const d of directives) {
        const hasInline = d.sources.some((s) => s.kind === "keyword" && s.keyword === "'unsafe-inline'");
        const hasEval = d.sources.some((s) => s.kind === "keyword" && s.keyword === "'unsafe-eval'");
        if (hasInline && hasEval) {
            issues.push({
                code: "unsafe-inline-with-unsafe-eval",
                level: "warning",
                message: `Directive "${d.name}" combines 'unsafe-inline' and 'unsafe-eval', which together nullify XSS protection.`,
                directive: d.name,
            });
        }
    }
    return issues;
};
export const ruleBroadScheme = (directives) => {
    const issues = [];
    for (const d of directives) {
        if (!FETCH_DIRECTIVES.has(d.name)) {
            continue;
        }
        for (const s of d.sources) {
            if (s.kind === "scheme" && s.scheme !== undefined && BROAD_SCHEMES.has(s.scheme)) {
                issues.push({
                    code: "broad-scheme",
                    level: "warning",
                    message: `Broad scheme "${s.raw}" in "${d.name}" allows any host over ${s.scheme}.`,
                    directive: d.name,
                    source: s.raw,
                });
            }
        }
    }
    return issues;
};
export const rulePolicyIgnored = (_directives, context = DEFAULT_CONTEXT) => {
    if (context.source !== "meta" || context.disposition !== "report") {
        return [];
    }
    return [
        {
            code: "policy-ignored",
            level: "error",
            message: "Content-Security-Policy-Report-Only is not supported in a <meta> element; browsers ignore the whole policy.",
        },
    ];
};
export const ruleIgnoredDirective = (directives, context = DEFAULT_CONTEXT) => {
    // A report-only meta policy is ignored as a whole; rulePolicyIgnored covers it.
    if (context.source === "meta" && context.disposition === "report") {
        return [];
    }
    const issues = [];
    for (const d of directives) {
        let where;
        if (context.source === "meta" && META_IGNORED_DIRECTIVES.has(d.name)) {
            where = "a policy delivered through a <meta> element";
        }
        else if (context.disposition === "report" && REPORT_ONLY_IGNORED_DIRECTIVES.has(d.name)) {
            where = "a Content-Security-Policy-Report-Only policy";
        }
        if (where !== undefined) {
            issues.push({
                code: "directive-ignored",
                level: "error",
                message: `Directive "${d.name}" is ignored in ${where}.`,
                directive: d.name,
            });
        }
    }
    return issues;
};
export const ALL_RULES = [
    ruleDuplicateDirective,
    ruleDuplicateSource,
    ruleUnknownDirective,
    ruleNoneWithOtherSources,
    ruleNoValueDirectiveWithArguments,
    ruleMissingSourceList,
    ruleDeprecatedDirective,
    ruleReportUriWithoutReportTo,
    ruleMissingDefaultOrScriptSrc,
    ruleStrictDynamicHostIgnored,
    ruleUnsafeInlineWithUnsafeEval,
    ruleBroadScheme,
    rulePolicyIgnored,
    ruleIgnoredDirective,
];
export function runRules(directives, context = DEFAULT_CONTEXT) {
    const issues = [];
    for (const rule of ALL_RULES) {
        issues.push(...rule(directives, context));
    }
    return issues;
}
