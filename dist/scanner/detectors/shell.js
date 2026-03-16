"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.detectShellInjection = detectShellInjection;
const SHELL_FUNCTIONS = new Set(['exec', 'execSync', 'spawn', 'spawnSync', 'execFile', 'execFileSync']);
function walkNode(node, callback) {
    callback(node);
    for (const key of Object.keys(node)) {
        const child = node[key];
        if (child && typeof child === 'object') {
            if (Array.isArray(child)) {
                child.forEach((c) => { if (c && typeof c === 'object' && 'type' in c)
                    walkNode(c, callback); });
            }
            else if ('type' in child) {
                walkNode(child, callback);
            }
        }
    }
}
function isSimpleStringLiteral(node) {
    return node.type === 'Literal' && typeof node.value === 'string';
}
function isShellCall(callee) {
    if (callee.type === 'Identifier' && SHELL_FUNCTIONS.has(callee.name)) {
        return callee.name;
    }
    if (callee.type === 'MemberExpression') {
        const prop = callee.property;
        if (prop.type === 'Identifier' && SHELL_FUNCTIONS.has(prop.name)) {
            return prop.name;
        }
    }
    return null;
}
function detectShellInjection(result) {
    const findings = [];
    walkNode(result.ast, (node) => {
        if (node.type !== 'CallExpression')
            return;
        const call = node;
        const fnName = isShellCall(call.callee);
        if (!fnName)
            return;
        if (call.arguments.length === 0)
            return;
        const firstArg = call.arguments[0];
        if (firstArg.type === 'SpreadElement')
            return;
        // exec/execSync: first arg should be a plain string literal
        // spawn/spawnSync: first arg is command, second is args array — command still shouldn't be dynamic
        if (!isSimpleStringLiteral(firstArg)) {
            const line = node.loc.start.line;
            const snippet = result.lines[line - 1]?.trim() ?? '';
            findings.push({
                type: 'SHELL_INJECTION',
                severity: 'high',
                line,
                column: node.loc.start.column,
                snippet,
                message: `${fnName}() called with a non-literal argument. Unsanitized input may lead to shell injection.`,
            });
        }
    });
    return findings;
}
//# sourceMappingURL=shell.js.map