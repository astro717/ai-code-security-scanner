/**
 * Python language support for the AI Code Security Scanner.
 *
 * This module implements a regex-based scan pass for Python files. It does not
 * use a full Python AST parser (no native bindings required) — instead, it
 * operates on the raw source lines with pattern matching. This is intentionally
 * conservative: it only flags patterns that are nearly always vulnerabilities
 * and has a very low false-positive rate.
 *
 * Architecture note:
 * ─────────────────
 * The scanner uses a language-agnostic LanguageParseResult interface. To add a
 * new language, create a parser module that returns a LanguageParseResult and
 * register its extensions in LANGUAGE_EXTENSIONS (cli.ts / server.ts).
 * No changes to the core finding/reporting pipeline are needed.
 */
import type { Finding } from './reporter';
export interface PythonParseResult {
    language: 'python';
    code: string;
    lines: string[];
    filePath: string;
}
export declare function parsePythonFile(filePath: string): PythonParseResult;
export declare function parsePythonCode(code: string, filePath?: string): PythonParseResult;
/**
 * Scans a parsed Python source for security vulnerabilities using pattern matching.
 * Returns findings in the same Finding format as JS/TS detectors.
 */
export declare function scanPython(result: PythonParseResult): Finding[];
//# sourceMappingURL=python-parser.d.ts.map