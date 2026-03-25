/**
 * Ruby language support for the AI Code Security Scanner.
 *
 * This module implements a regex-based scan pass for Ruby files. It operates on
 * raw source lines with pattern matching — no native Ruby bindings required.
 * Patterns focus on Rails-specific vulnerabilities common in AI-generated code.
 *
 * Covered vulnerability classes:
 *   - SQL_INJECTION (string interpolation in ActiveRecord queries)
 *   - XSS (html_safe, raw with user input)
 *   - COMMAND_INJECTION (backtick execution, system(), exec(), Open3 with interpolation)
 *   - SECRET_HARDCODED (hardcoded credentials)
 *   - MASS_ASSIGNMENT (permit(:all) or unrestricted permit)
 *   - PATH_TRAVERSAL (File.read/open with user input)
 *   - INSECURE_RANDOM (rand() for security use)
 *   - WEAK_CRYPTO (MD5, SHA1 via Digest library)
 *   - OPEN_REDIRECT (redirect_to with user input)
 *   - EVAL_INJECTION (eval with user input)
 */
import type { Finding } from './reporter';
export interface RubyParseResult {
    language: 'ruby';
    code: string;
    lines: string[];
    filePath: string;
}
export declare function parseRubyFile(filePath: string): RubyParseResult;
export declare function parseRubyCode(code: string, filePath?: string): RubyParseResult;
/**
 * Scans a parsed Ruby source for security vulnerabilities using pattern matching.
 * Returns findings in the same Finding format as other language detectors.
 */
export declare function scanRuby(result: RubyParseResult): Finding[];
//# sourceMappingURL=ruby-parser.d.ts.map