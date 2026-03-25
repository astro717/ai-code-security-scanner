import { ParseResult } from '../parser';
import { Finding } from '../reporter';
/**
 * Detects JWT none-algorithm vulnerability:
 *   1. jwt.verify(token, secret) called WITHOUT an options object specifying algorithms
 *      (missing algorithms whitelist allows 'none' algorithm in older jsonwebtoken versions)
 *   2. jwt.verify(token, secret, { algorithms: ['none'] }) — explicitly set to none
 *   3. jwt.decode(token, { complete: true }) — jwt.decode bypasses signature verification entirely
 */
export declare function detectJWTNoneAlgorithm(result: ParseResult): Finding[];
//# sourceMappingURL=jwtNone.d.ts.map