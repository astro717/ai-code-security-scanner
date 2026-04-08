"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.detectWeakCrypto = detectWeakCrypto;
const utils_1 = require("../utils");
const WEAK_HASH_ALGORITHMS = new Set(['md5', 'md4', 'sha1', 'sha-1']);
/**
 * Detects usage of weak cryptographic hash algorithms:
 *   - crypto.createHash('md5')
 *   - crypto.createHash('sha1')
 *   - createHash('md5') after destructuring
 */
function detectWeakCrypto(result) {
    const findings = [];
    const reported = new Set();
    (0, utils_1.walkNode)(result.ast, (node) => {
        if (node.type !== 'CallExpression')
            return;
        const call = node;
        // Match createHash(...) — as bare call or crypto.createHash(...)
        let isCreateHash = false;
        if (call.callee.type === 'Identifier') {
            isCreateHash = call.callee.name === 'createHash';
        }
        else if (call.callee.type === 'MemberExpression' && !call.callee.computed) {
            const prop = call.callee.property;
            if (prop.type === 'Identifier') {
                isCreateHash = prop.name === 'createHash';
            }
        }
        if (!isCreateHash)
            return;
        if (call.arguments.length === 0)
            return;
        const firstArg = call.arguments[0];
        if (firstArg.type === 'SpreadElement')
            return;
        // Only flag if the algorithm is a known weak literal string
        if (firstArg.type === 'Literal' &&
            typeof (firstArg.value) === 'string') {
            const alg = firstArg.value.toLowerCase();
            if (WEAK_HASH_ALGORITHMS.has(alg)) {
                const line = node.loc.start.line;
                if (!reported.has(line)) {
                    reported.add(line);
                    findings.push({
                        type: 'WEAK_CRYPTO',
                        severity: 'high',
                        line,
                        column: node.loc.start.column,
                        snippet: result.lines[line - 1]?.trim() ?? '',
                        message: `crypto.createHash('${alg}') uses a weak algorithm. ` +
                            `MD5 and SHA-1 are cryptographically broken and must not be used for password hashing, ` +
                            `digital signatures, or token generation. Use SHA-256 or SHA-3 instead. ` +
                            `For passwords, use bcrypt, scrypt, or Argon2.`,
                        confidence: 0.88,
                    });
                }
            }
        }
    });
    return findings;
}
//# sourceMappingURL=weakCrypto.js.map