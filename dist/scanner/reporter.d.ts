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
    /**
     * Detection confidence score in the range [0.0, 1.0].
     * High-specificity patterns (exact API matches, literal checks) use 0.9+.
     * Broad heuristic patterns (generic regexes, keyword proximity) use lower values.
     * Absent means the detector did not emit a confidence estimate.
     */
    confidence?: number;
}
export interface ScanSummary {
    critical: number;
    high: number;
    medium: number;
    low: number;
    total: number;
}
/**
 * Deduplicates findings by composite key: file + line + type.
 *
 * When multiple detectors independently flag the same code location with the
 * same vulnerability type, only the finding with the highest confidence score
 * is kept (or the first one encountered when confidence is equal).
 *
 * This deliberately allows different types on the same line — a single line can
 * legitimately have both SQL_INJECTION and XSS findings.
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