"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.detectJWTSecrets = detectJWTSecrets;
const utils_1 = require("../utils");
function isStringLiteral(node) {
    return node.type === 'Literal' && typeof node.value === 'string';
}
function getStringValue(node) {
    if (isStringLiteral(node))
        return node.value;
    return null;
}
/**
 * Resolves the secret argument from a jwt.sign() / jsonwebtoken.sign() call.
 * The signature is: sign(payload, secretOrPrivateKey, [options])
 * Returns the second argument node, or null if not present.
 */
function getSecretArgNode(call) {
    if (call.arguments.length < 2)
        return null;
    const arg = call.arguments[1];
    if (arg.type === 'SpreadElement')
        return null;
    return arg;
}
function detectJWTSecrets(result) {
    const findings = [];
    const reported = new Set();
    (0, utils_1.walkNode)(result.ast, (node) => {
        if (node.type !== 'CallExpression')
            return;
        const call = node;
        // Match jwt.sign() or jsonwebtoken.sign() (member expression)
        const isMemberSign = call.callee.type === 'MemberExpression' &&
            !call.callee.computed &&
            call.callee.property.type === 'Identifier' &&
            call.callee.property.name === 'sign';
        // Also match bare sign() — less common but possible after destructuring
        const isBareSign = call.callee.type === 'Identifier' &&
            call.callee.name === 'sign';
        if (!isMemberSign && !isBareSign)
            return;
        const secretNode = getSecretArgNode(call);
        if (!secretNode)
            return;
        const line = node.loc.start.line;
        if (reported.has(line))
            return;
        const secretValue = getStringValue(secretNode);
        // Case 1: secret is a hardcoded string literal
        if (secretValue !== null) {
            reported.add(line);
            const isShort = secretValue.length < 32;
            const redacted = secretValue.length <= 8
                ? '****'
                : secretValue.slice(0, 4) + '****' + secretValue.slice(-4);
            if (isShort) {
                findings.push({
                    type: 'JWT_WEAK_SECRET',
                    severity: 'critical',
                    line,
                    column: node.loc.start.column,
                    snippet: result.lines[line - 1]?.trim() ?? '',
                    message: `jwt.sign() called with a short hardcoded secret ("${redacted}", ${secretValue.length} chars). JWT secrets must be ≥32 chars and stored in environment variables, not source code.`,
                });
            }
            else {
                findings.push({
                    type: 'JWT_HARDCODED_SECRET',
                    severity: 'critical',
                    line,
                    column: node.loc.start.column,
                    snippet: result.lines[line - 1]?.trim() ?? '',
                    message: `jwt.sign() called with a hardcoded string secret ("${redacted}"). Store JWT secrets in environment variables (e.g. process.env.JWT_SECRET) and never commit them to source.`,
                });
            }
            return;
        }
        // Case 2: secret comes from a config object property with a string literal value
        // e.g. sign(payload, config.secret) where we can trace the object literal
        // We handle the simpler case: sign(payload, { secret: 'hardcoded' }) — object literal as second arg
        if (secretNode.type === 'ObjectExpression') {
            const obj = secretNode;
            for (const prop of obj.properties) {
                if (prop.type !== 'Property')
                    continue;
                const p = prop;
                const keyName = p.key.type === 'Identifier'
                    ? p.key.name
                    : isStringLiteral(p.key)
                        ? p.key.value
                        : null;
                if (!keyName)
                    continue;
                const isSecretKey = /^(secret|privateKey|private_key|secretOrPrivateKey)$/i.test(keyName);
                if (!isSecretKey)
                    continue;
                const valStr = getStringValue(p.value);
                if (valStr !== null) {
                    if (!reported.has(line)) {
                        reported.add(line);
                        const isShort = valStr.length < 32;
                        const redacted = valStr.length <= 8
                            ? '****'
                            : valStr.slice(0, 4) + '****' + valStr.slice(-4);
                        findings.push({
                            type: isShort ? 'JWT_WEAK_SECRET' : 'JWT_HARDCODED_SECRET',
                            severity: 'critical',
                            line,
                            column: node.loc.start.column,
                            snippet: result.lines[line - 1]?.trim() ?? '',
                            message: `jwt.sign() config object has hardcoded "${keyName}" value ("${redacted}"${isShort ? `, only ${valStr.length} chars` : ''}). Use process.env for secrets.`,
                        });
                    }
                    break;
                }
            }
        }
    });
    return findings;
}
//# sourceMappingURL=jwt.js.map