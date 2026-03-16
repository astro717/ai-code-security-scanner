export type Severity = 'critical' | 'high' | 'medium' | 'low';
export interface Finding {
    type: string;
    severity: Severity;
    line: number;
    column: number;
    snippet: string;
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
export declare function summarize(findings: Finding[]): ScanSummary;
export declare function formatJSON(findings: Finding[]): string;
export declare function printFindings(findings: Finding[], targetPath: string): Promise<void>;
//# sourceMappingURL=reporter.d.ts.map