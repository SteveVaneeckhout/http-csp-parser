import type { Issue, ParsedSource } from "./types.js";
export interface ClassifyResult {
  readonly source: ParsedSource;
  readonly errors: readonly Issue[];
  readonly warnings: readonly Issue[];
}
export declare function classifySource(token: string, directiveName: string): ClassifyResult;
