import { ParseResult } from '../parser';
import { Finding } from '../reporter';
/**
 * Detects ReDoS (Regex Denial of Service) via dynamic RegExp construction:
 *   - new RegExp(userInput)
 *   - new RegExp(userInput, flags)
 * where the pattern argument is not a static string/regex literal.
 */
export declare function detectReDoS(result: ParseResult): Finding[];
//# sourceMappingURL=redos.d.ts.map