"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.detectSQLInjection = detectSQLInjection;
const SQL_FUNCTION_NAMES = /^(query|execute|raw|db|sql|run|all|get|prepare)$/i;
const SQL_MEMBER_NAMES = /\.(query|execute|raw|run|all|get|prepare)\s*\(/;
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
function isStringLiteral(node) {
    return node.type === 'Literal' && typeof node.value === 'string';
}
function isDynamic(node) {
    if (isStringLiteral(node))
        return false;
    if (node.type === 'TemplateLiteral') {
        return node.expressions.length > 0;
    }
    if (node.type === 'BinaryExpression') {
        const bin = node;
        if (bin.operator === '+') {
            return isDynamic(bin.left) || isDynamic(bin.right) ||
                (!isStringLiteral(bin.left) || !isStringLiteral(bin.right));
        }
    }
    return true;
}
function isSQLCallExpression(node) {
    const callee = node.callee;
    if (callee.type === 'Identifier') {
        return SQL_FUNCTION_NAMES.test(callee.name);
    }
    if (callee.type === 'MemberExpression') {
        const prop = callee.property;
        if (prop.type === 'Identifier')
            return SQL_FUNCTION_NAMES.test(prop.name);
    }
    return false;
}
function detectSQLInjection(result) {
    const findings = [];
    walkNode(result.ast, (node) => {
        if (node.type !== 'CallExpression')
            return;
        const call = node;
        if (!isSQLCallExpression(call))
            return;
        if (call.arguments.length === 0)
            return;
        const firstArg = call.arguments[0];
        if (firstArg.type === 'SpreadElement')
            return;
        if (isDynamic(firstArg)) {
            const line = node.loc.start.line;
            const snippet = result.lines[line - 1]?.trim() ?? '';
            findings.push({
                type: 'SQL_INJECTION',
                severity: 'critical',
                line,
                column: node.loc.start.column,
                snippet,
                message: 'Dynamic value passed directly to SQL query function. Use parameterized queries.',
            });
        }
    });
    return findings;
}
//# sourceMappingURL=sql.js.map