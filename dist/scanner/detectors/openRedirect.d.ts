import { ParseResult } from '../parser';
import { Finding } from '../reporter';
/**
 * Detects calls to res.redirect() where the argument is not a static string.
 * Dynamic redirect targets can lead to open redirect vulnerabilities.
 */
export declare function detectOpenRedirect(result: ParseResult): Finding[];
//# sourceMappingURL=openRedirect.d.ts.map