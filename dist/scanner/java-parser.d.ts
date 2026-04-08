/**
 * Java language support for the AI Code Security Scanner.
 *
 * This module implements a regex-based scan pass for Java files. Like the Python
 * and Go scanners, it operates on raw source lines with pattern matching — no
 * Java AST parser or native bindings required. The patterns are deliberately
 * conservative to minimise false positives.
 *
 * Covered vulnerability classes:
 *   - SQL_INJECTION (string concatenation in JDBC queries)
 *   - COMMAND_INJECTION (Runtime.exec with user input)
 *   - SECRET_HARDCODED (hardcoded credentials)
 *   - WEAK_CRYPTO (MD5, SHA-1, DES)
 *   - PATH_TRAVERSAL (File constructor with user input)
 *   - INSECURE_RANDOM (java.util.Random for security)
 *   - EVAL_INJECTION (ScriptEngine.eval with dynamic input)
 *   - UNSAFE_DESERIALIZATION (ObjectInputStream.readObject)
 *   - XSS (direct output of user input in servlets)
 *   - SSRF (URL/HttpURLConnection with user input)
 *   - PERFORMANCE_N_PLUS_ONE (JDBC/JPA query inside a loop)
 */
import type { Finding } from './reporter';
export interface JavaParseResult {
    language: 'java';
    code: string;
    lines: string[];
    filePath: string;
}
export declare function parseJavaFile(filePath: string): JavaParseResult;
export declare function parseJavaCode(code: string, filePath?: string): JavaParseResult;
/**
 * Scans a parsed Java source for security vulnerabilities using pattern matching.
 * Returns findings in the same Finding format as JS/TS, Python, and Go detectors.
 */
export declare function scanJava(result: JavaParseResult): Finding[];
//# sourceMappingURL=java-parser.d.ts.map