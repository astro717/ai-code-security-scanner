export type Severity = 'critical' | 'high' | 'medium' | 'low';
export interface VulnerabilityPattern {
    id: string;
    name: string;
    severity: Severity;
    description: string;
    remediation: string;
}
export declare const VULNERABILITY_PATTERNS: Record<string, VulnerabilityPattern>;
//# sourceMappingURL=patterns.d.ts.map