import { Finding } from './reporter';
import type { FixResult } from './fixer';
export declare const SARIF_RULE_DESCRIPTIONS: Record<string, string>;
export declare function buildSARIF(findings: Finding[], toolName?: string, fixResults?: FixResult[]): object;
//# sourceMappingURL=sarif.d.ts.map