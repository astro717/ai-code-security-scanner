import { ParseResult } from '../parser';
import { Finding } from '../reporter';
/**
 * Detects SSRF (Server-Side Request Forgery): calls to fetch(), axios.get/post(),
 * http.get(), https.get(), etc. where the URL argument is dynamic (a variable
 * or a template literal with expressions) rather than a static string.
 *
 * Additionally performs single-scope taint tracking: if the URL variable was
 * assigned from req.query / req.body / req.params / req.headers (including
 * multi-hop assignments), a higher-confidence SSRF finding is emitted.
 */
export declare function detectSSRF(result: ParseResult): Finding[];
//# sourceMappingURL=ssrf.d.ts.map