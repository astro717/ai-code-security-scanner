import { Finding } from './reporter';
/**
 * Produces a self-contained single-file HTML report for the given findings.
 *
 * @param findings - The filtered list of findings to render.
 * @param scanRoot - Absolute path of the scan target (used to shorten file paths).
 * @param generatedAt - ISO timestamp to display in the report header.
 */
export declare function buildHTMLReport(findings: Finding[], scanRoot: string, generatedAt?: string): string;
//# sourceMappingURL=htmlReport.d.ts.map