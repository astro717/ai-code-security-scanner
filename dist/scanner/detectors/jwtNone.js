"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.detectJWTNoneAlgorithm = detectJWTNoneAlgorithm;
const utils_1 = require("../utils");
function isStringValue(node, value) {
    return node.type === 'Literal' && node.value === value;
}
/**
 * Looks inside an options object for { algorithms: [...] } or { algorithm: '...' }
 * Returns true if 'none' algorithm is explicitly set.
 */
function hasNoneAlgorithm(optionsNode) {
    if (optionsNode.type !== 'ObjectExpression')
        return false;
    const obj = optionsNode;
    for (const prop of obj.properties) {
        if (prop.type !== 'Property')
            continue;
        const p = prop;
        const keyName = p.key.type === 'Identifier'
            ? p.key.name
            : p.key.type === 'Literal'
                ? String(p.key.value)
                : null;
        if (!keyName)
            continue;
        if (keyName === 'algorithm' && isStringValue(p.value, 'none')) {
            return true;
        }
        if (keyName === 'algorithms' && p.value.type === 'ArrayExpression') {
            const arr = p.value;
            if (arr.elements.some((el) => el && isStringValue(el, 'none'))) {
                return true;
            }
        }
    }
    return false;
}
/**
 * Detects JWT none-algorithm vulnerability:
 *   1. jwt.verify(token, secret) called WITHOUT an options object specifying algorithms
 *      (missing algorithms whitelist allows 'none' algorithm in older jsonwebtoken versions)
 *   2. jwt.verify(token, secret, { algorithms: ['none'] }) — explicitly set to none
 *   3. jwt.decode(token, { complete: true }) — jwt.decode bypasses signature verification entirely
 */
function detectJWTNoneAlgorithm(result) {
    const findings = [];
    const reported = new Set();
    (0, utils_1.walkNode)(result.ast, (node) => {
        if (node.type !== 'CallExpression')
            return;
        const call = node;
        if (call.callee.type !== 'MemberExpression')
            return;
        const member = call.callee;
        if (member.property.type !== 'Identifier')
            return;
        const methodName = member.property.name;
        const line = node.loc.start.line;
        if (reported.has(line))
            return;
        // Detect jwt.verify() with no options or no algorithms whitelist
        if (methodName === 'verify') {
            const args = call.arguments;
            // jwt.verify(token, secret) — no options at all (missing algorithms whitelist)
            if (args.length < 3) {
                reported.add(line);
                findings.push({
                    type: 'JWT_NONE_ALGORITHM',
                    severity: 'high',
                    line,
                    column: node.loc.start.column,
                    snippet: result.lines[line - 1]?.trim() ?? '',
                    message: 'jwt.verify() called without an explicit algorithms whitelist. ' +
                        'In vulnerable versions of jsonwebtoken this allows the "none" algorithm, ' +
                        'letting attackers forge tokens without a signature. ' +
                        'Always pass { algorithms: [\'RS256\'] } or your expected algorithm.',
                });
                return;
            }
            // jwt.verify(token, secret, options) — check if algorithms: ['none']
            const optionsArg = args[2];
            if (optionsArg && optionsArg.type !== 'SpreadElement' && hasNoneAlgorithm(optionsArg)) {
                reported.add(line);
                findings.push({
                    type: 'JWT_NONE_ALGORITHM',
                    severity: 'critical',
                    line,
                    column: node.loc.start.column,
                    snippet: result.lines[line - 1]?.trim() ?? '',
                    message: 'jwt.verify() called with algorithm set to "none". ' +
                        'The "none" algorithm disables signature verification entirely, ' +
                        'allowing any unsigned token to be accepted. Remove "none" from the algorithms list.',
                });
            }
        }
        // Detect jwt.decode() — never verifies signature
        if (methodName === 'decode') {
            reported.add(line);
            findings.push({
                type: 'JWT_DECODE_NO_VERIFY',
                severity: 'high',
                line,
                column: node.loc.start.column,
                snippet: result.lines[line - 1]?.trim() ?? '',
                message: 'jwt.decode() does not verify the token signature. ' +
                    'Use jwt.verify() with an explicit algorithms whitelist to authenticate tokens. ' +
                    'Only use jwt.decode() for reading claims from already-verified tokens.',
            });
        }
    });
    return findings;
}
//# sourceMappingURL=jwtNone.js.map