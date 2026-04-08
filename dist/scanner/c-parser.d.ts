/**
 * C/C++ language support for the AI Code Security Scanner.
 *
 * This module implements a regex-based scan pass for C and C++ files (.c, .cpp,
 * .cc, .cxx, .h, .hpp). It operates on raw source lines with pattern matching —
 * no native compilation or libclang required. Patterns are conservative to
 * minimise false positives in real-world systems code.
 *
 * Covered vulnerability classes:
 *   - BUFFER_OVERFLOW (unsafe string/buffer functions: gets, strcpy, strcat, sprintf, scanf)
 *   - FORMAT_STRING (printf/fprintf family with non-literal format strings)
 *   - COMMAND_INJECTION_C (system() / popen() / exec*() family — user-controlled command execution)
 *   - SECRET_HARDCODED (hardcoded credentials in string literals)
 *   - PATH_TRAVERSAL (fopen/open with user-controlled paths)
 *   - INSECURE_RANDOM (rand() / srand(time()) for security use)
 *   - WEAK_CRYPTO (MD5, SHA1 via common OpenSSL library calls)
 */
import type { Finding } from './reporter';
export interface CParseResult {
    language: 'c';
    code: string;
    lines: string[];
    filePath: string;
}
export declare function parseCFile(filePath: string): CParseResult;
export declare function parseCCode(code: string, filePath?: string): CParseResult;
/**
 * Scans a parsed C/C++ source for security vulnerabilities using pattern matching.
 * Returns findings in the same Finding format as other language detectors.
 */
export declare function scanC(result: CParseResult): Finding[];
//# sourceMappingURL=c-parser.d.ts.map