/**
 * C# language support for the AI Code Security Scanner.
 *
 * This module implements a regex-based scan pass for C# files. It operates on
 * raw source lines with pattern matching — no Roslyn or native bindings required.
 * The patterns are deliberately conservative to minimise false positives.
 *
 * Covered vulnerability classes:
 *   - SQL_INJECTION (string interpolation / concatenation in ADO.NET / EF queries)
 *   - COMMAND_INJECTION (Process.Start with user input)
 *   - SECRET_HARDCODED (hardcoded credentials)
 *   - WEAK_CRYPTO (MD5, SHA1, DES, RC2)
 *   - PATH_TRAVERSAL (File/Directory access with user input)
 *   - INSECURE_RANDOM (System.Random for security use)
 *   - UNSAFE_DESERIALIZATION (BinaryFormatter deserializes untrusted data)
 *   - XSS (Response.Write with unencoded user input in ASP.NET)
 *   - SSRF (HttpClient/WebClient/WebRequest with user input)
 *   - OPEN_REDIRECT (Response.Redirect with user input)
 */
import type { Finding } from './reporter';
export interface CSharpParseResult {
    language: 'csharp';
    code: string;
    lines: string[];
    filePath: string;
}
export declare function parseCSharpFile(filePath: string): CSharpParseResult;
export declare function parseCSharpCode(code: string, filePath?: string): CSharpParseResult;
/**
 * Scans a parsed C# source for security vulnerabilities using pattern matching.
 * Returns findings in the same Finding format as other language detectors.
 */
export declare function scanCSharp(result: CSharpParseResult): Finding[];
//# sourceMappingURL=csharp-parser.d.ts.map