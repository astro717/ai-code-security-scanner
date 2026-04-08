"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.detectInsecureRandom = detectInsecureRandom;
const utils_1 = require("../utils");
// Variable name patterns that suggest security-sensitive usage
const SECURITY_NAME_PATTERNS = [
    /token/i, /secret/i, /password/i, /passwd/i, /session/i, /csrf/i,
    /nonce/i, /salt/i, /\bkey\b/i, /\bkeys\b/i, /\bid\b/i, /\bids\b/i,
    /apikey/i, /api_key/i, /authtoken/i, /auth_token/i, /accesstoken/i,
    /reset/i, /verify/i, /otp/i, /pin\b/i,
];
function isSecuritySensitiveName(name) {
    return SECURITY_NAME_PATTERNS.some((re) => re.test(name));
}
function isMathRandomCall(node) {
    if (node.type !== 'CallExpression')
        return false;
    const call = node;
    if (call.callee.type !== 'MemberExpression')
        return false;
    const callee = call.callee;
    if (callee.computed)
        return false;
    const obj = callee.object;
    const prop = callee.property;
    return (obj.type === 'Identifier' && obj.name === 'Math' &&
        prop.type === 'Identifier' && prop.name === 'random');
}
function detectInsecureRandom(result) {
    const findings = [];
    const reported = new Set(); // avoid duplicate findings for same line
    (0, utils_1.walkNode)(result.ast, (node) => {
        // 1. Variable assignment: const resetToken = Math.random() (or derived expression)
        if (node.type === 'VariableDeclarator') {
            const decl = node;
            const idName = decl.id.type === 'Identifier' ? decl.id.name : '';
            if (idName && isSecuritySensitiveName(idName) && decl.init) {
                // Check if init or any sub-expression is Math.random()
                let foundRandom = false;
                (0, utils_1.walkNode)(decl.init, (child) => {
                    if (isMathRandomCall(child))
                        foundRandom = true;
                });
                if (foundRandom) {
                    const line = node.loc.start.line;
                    if (!reported.has(line)) {
                        reported.add(line);
                        findings.push({
                            type: 'INSECURE_RANDOM',
                            severity: 'medium',
                            line,
                            column: node.loc.start.column,
                            snippet: result.lines[line - 1]?.trim() ?? '',
                            message: `Math.random() used to generate "${idName}". Math.random() is not cryptographically secure — use crypto.randomBytes() or crypto.getRandomValues() instead.`,
                            confidence: 0.75,
                        });
                    }
                }
            }
        }
        // 2. Assignment expression: obj.sessionToken = Math.random() * ...
        if (node.type === 'AssignmentExpression') {
            const assign = node;
            const left = assign.left;
            let assignedName = '';
            if (left.type === 'Identifier') {
                assignedName = left.name;
            }
            else if (left.type === 'MemberExpression' && !left.computed) {
                const prop = left.property;
                assignedName = prop.type === 'Identifier' ? prop.name : '';
            }
            if (assignedName && isSecuritySensitiveName(assignedName)) {
                let foundRandom = false;
                (0, utils_1.walkNode)(assign.right, (child) => {
                    if (isMathRandomCall(child))
                        foundRandom = true;
                });
                if (foundRandom) {
                    const line = node.loc.start.line;
                    if (!reported.has(line)) {
                        reported.add(line);
                        findings.push({
                            type: 'INSECURE_RANDOM',
                            severity: 'medium',
                            line,
                            column: node.loc.start.column,
                            snippet: result.lines[line - 1]?.trim() ?? '',
                            message: `Math.random() assigned to "${assignedName}". Math.random() is not cryptographically secure — use crypto.randomBytes() or crypto.getRandomValues() instead.`,
                            confidence: 0.75,
                        });
                    }
                }
            }
        }
        // 3. Math.random() passed directly to btoa()
        if (node.type === 'CallExpression') {
            const call = node;
            const callee = call.callee;
            const fnName = callee.type === 'Identifier' ? callee.name :
                (callee.type === 'MemberExpression' && !callee.computed)
                    ? (callee.property.type === 'Identifier'
                        ? callee.property.name
                        : '')
                    : '';
            if (fnName === 'btoa' || fnName === 'toString' || fnName === 'encode') {
                for (const arg of call.arguments) {
                    if (arg.type === 'SpreadElement')
                        continue;
                    let foundRandom = false;
                    (0, utils_1.walkNode)(arg, (child) => {
                        if (isMathRandomCall(child))
                            foundRandom = true;
                    });
                    if (foundRandom) {
                        const line = node.loc.start.line;
                        if (!reported.has(line)) {
                            reported.add(line);
                            findings.push({
                                type: 'INSECURE_RANDOM',
                                severity: 'medium',
                                line,
                                column: node.loc.start.column,
                                snippet: result.lines[line - 1]?.trim() ?? '',
                                message: `Math.random() value encoded via ${fnName}(). This is not cryptographically secure. Use crypto.randomBytes() for tokens and credentials.`,
                                confidence: 0.75,
                            });
                        }
                    }
                }
            }
        }
        // 4. Math.random() concatenated in a string that's assigned to a security-sensitive var
        // (Covered by patterns 1 & 2 via the recursive walkNode on the right-hand side)
        // 5. return Math.random() inside a security-sensitive function (e.g. generateToken)
        if (node.type === 'FunctionDeclaration' || node.type === 'FunctionExpression' || node.type === 'ArrowFunctionExpression') {
            const fnNode = node;
            const fnName = 'id' in fnNode && fnNode.id ? fnNode.id.name : '';
            if (fnName && isSecuritySensitiveName(fnName)) {
                // Walk the body looking for a return with Math.random()
                (0, utils_1.walkNode)(fnNode.body, (child) => {
                    if (child.type === 'ReturnStatement') {
                        const ret = child;
                        if (ret.argument) {
                            let foundRandom = false;
                            (0, utils_1.walkNode)(ret.argument, (grandchild) => {
                                if (isMathRandomCall(grandchild))
                                    foundRandom = true;
                            });
                            if (foundRandom) {
                                const line = child.loc.start.line;
                                if (!reported.has(line)) {
                                    reported.add(line);
                                    findings.push({
                                        type: 'INSECURE_RANDOM',
                                        severity: 'medium',
                                        line,
                                        column: child.loc.start.column,
                                        snippet: result.lines[line - 1]?.trim() ?? '',
                                        message: `Math.random() returned from "${fnName}()". Math.random() is not cryptographically secure — use crypto.randomBytes() or crypto.getRandomValues() instead.`,
                                        confidence: 0.75,
                                    });
                                }
                            }
                        }
                    }
                });
            }
        }
    });
    return findings;
}
//# sourceMappingURL=insecureRandom.js.map