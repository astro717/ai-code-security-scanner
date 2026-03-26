export type Severity = 'critical' | 'high' | 'medium' | 'low';
/**
 * The canonical set of finding type strings emitted by the built-in detectors.
 * Export this constant so consumers (e.g. CLI --ignore-type validation) can
 * check whether a user-supplied type string is recognised.
 */
export declare const KNOWN_TYPES: Set<string>;
export interface Finding {
    type: string;
    severity: Severity;
    line: number;
    column: number;
    /** Code snippet at the finding location. May be absent for some detectors. */
    snippet?: string;
    message: string;
    file?: string;
}
export interface ScanSummary {
    critical: number;
    high: number;
    medium: number;
    low: number;
    total: number;
}
/**
 * Removes duplicate findings based on a stable key of (type, file, line, column).
 * When multiple detectors independently flag the same code location with the same
 * finding type, only the first occurrence is kept. Preserves original order.
 */
export declare function deduplicateFindings(findings: Finding[]): Finding[];
export declare function summarize(findings: Finding[]): ScanSummary;
export declare function formatJSON(findings: Finding[]): string;
/**
 * Returns the same structured text that `printFindings` writes to the
 * terminal, but without ANSI colour codes so it is suitable for writing to a
 * file via --output.
 */
export declare function formatFindingsText(findings: Finding[], targetPath: string): string;
export declare function printFindings(findings: Finding[], targetPath: string): Promise<void>;
//# sourceMappingURL=reporter.d.ts.map