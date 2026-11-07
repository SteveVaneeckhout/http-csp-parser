import type { Issue, ParsedDirective, PolicyDisposition, PolicySource } from "./types.js";
export interface PolicyContext {
    readonly source: PolicySource;
    readonly disposition: PolicyDisposition;
}
export declare const DEFAULT_CONTEXT: PolicyContext;
export type Rule = (directives: readonly ParsedDirective[], context?: PolicyContext) => readonly Issue[];
export declare const ruleDuplicateDirective: Rule;
export declare const ruleDuplicateSource: Rule;
export declare const ruleUnknownDirective: Rule;
export declare const ruleNoneWithOtherSources: Rule;
export declare const ruleNoValueDirectiveWithArguments: Rule;
export declare const ruleMissingSourceList: Rule;
export declare const ruleDeprecatedDirective: Rule;
export declare const ruleReportUriWithoutReportTo: Rule;
export declare const ruleMissingDefaultOrScriptSrc: Rule;
export declare const ruleStrictDynamicHostIgnored: Rule;
export declare const ruleUnsafeInlineWithUnsafeEval: Rule;
export declare const ruleBroadScheme: Rule;
export declare const rulePolicyIgnored: Rule;
export declare const ruleIgnoredDirective: Rule;
export declare const ALL_RULES: readonly Rule[];
export declare function runRules(directives: readonly ParsedDirective[], context?: PolicyContext): readonly Issue[];
