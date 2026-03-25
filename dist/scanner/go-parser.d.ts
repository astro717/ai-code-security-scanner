/**
 * Go language support for the AI Code Security Scanner.
 *
 * This module implements a regex-based scan pass for Go files. Like the Python
 * scanner, it operates on raw source lines with pattern matching — no Go AST
 * parser or native bindings required. The patterns are deliberately conservative
 * to minimise false positives.
 *
 * Covered vulnerability classes:
 *   - SSRF (net/http with user input)
 *   - SQL_INJECTION (fmt.Sprintf in queries)
 *   - COMMAND_INJECTION (exec.Command with user input)
 *   - SECRET_HARDCODED (hardcoded credentials)
 *   - EVAL_INJECTION (unsafe reflect / template execution)
 *   - WEAK_CRYPTO (md5, sha1)
 *   - PATH_TRAVERSAL (filepath.Join with user input)
 *   - INSECURE_RANDOM (math/rand for security)
 */
import type { Finding } from './reporter';
export interface GoParseResult {
    language: 'go';
    code: string;
    lines: string[];
    filePath: string;
}
export declare function parseGoFile(filePath: string): GoParseResult;
export declare function parseGoCode(code: string, filePath?: string): GoParseResult;
/**
 * Scans a parsed Go source for security vulnerabilities using pattern matching.
 * Returns findings in the same Finding format as JS/TS and Python detectors.
 */
export declare function scanGo(result: GoParseResult): Finding[];
//# sourceMappingURL=go-parser.d.ts.map