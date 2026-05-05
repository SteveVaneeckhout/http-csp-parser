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
export declare function tokenize(input: string): TokenizeResult;
