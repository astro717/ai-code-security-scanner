import { ParseResult } from '../parser';
import { Finding } from '../reporter';
/**
 * Detects usage of weak cryptographic hash algorithms:
 *   - crypto.createHash('md5')
 *   - crypto.createHash('sha1')
 *   - createHash('md5') after destructuring
 */
export declare function detectWeakCrypto(result: ParseResult): Finding[];
//# sourceMappingURL=weakCrypto.d.ts.map