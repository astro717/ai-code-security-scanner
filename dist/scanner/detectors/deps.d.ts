import { Finding } from '../reporter';
export declare function checkCVEMapStaleness(): void;
export declare const KNOWN_VULNERABLE: Record<string, {
    below: string;
    severity: 'critical' | 'high' | 'medium';
    cve: string;
}>;
export declare function parseVersion(v: string): number[];
export declare function isBelow(current: string, threshold: string): boolean;
/**
 * Scan a package.json provided as a raw JSON string (e.g. from the scan server
 * when the client uploads the file contents directly).
 */
export declare function detectUnsafeDepsFromJson(packageJsonStr: string): Finding[];
/**
 * Scan a project directory for an unsafe package.json. Also checks for a
 * missing lockfile. Used by the CLI when scanning a directory target.
 */
export declare function detectUnsafeDeps(projectDir: string): Finding[];
//# sourceMappingURL=deps.d.ts.map