"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.detectSQLInjection = detectSQLInjection;
const SQL_FUNCTION_NAMES = /^(query|execute|raw|db|sql|run|all|get|prepare)$/i;
const SQL_MEMBER_NAMES = /\.(query|execute|raw|run|all|get|prepare)\s*\(/; // kept for reference
// ORM raw-query methods: prisma.$queryRaw, prisma.$executeRaw, repository.query
const ORM_RAW_METHODS = /^\$(queryRaw|executeRaw|queryRawUnsafe|executeRawUnsafe)$/;
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
        if (prop.type === 'Identifier') {
            return SQL_FUNCTION_NAMES.test(prop.name) || ORM_RAW_METHODS.test(prop.name);
        }
    }
    return false;
}
function isORMTaggedTemplate(node) {
    const tag = node.tag;
    if (tag.type !== 'MemberExpression')
        return false;
    const prop = tag.property;
    if (prop.type !== 'Identifier')
        return false;
    return ORM_RAW_METHODS.test(prop.name);
}
function detectSQLInjection(result) {
    const findings = [];
    const reported = new Set();
    walkNode(result.ast, (node) => {
        // Case 1: CallExpression — db.query(dynamic), repository.query(dynamic), prisma.$queryRaw(dynamic)
        if (node.type === 'CallExpression') {
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
                if (!reported.has(line)) {
                    reported.add(line);
                    findings.push({
                        type: 'SQL_INJECTION',
                        severity: 'critical',
                        line,
                        column: node.loc.start.column,
                        snippet: result.lines[line - 1]?.trim() ?? '',
                        message: 'Dynamic value passed directly to SQL query function. Use parameterized queries.',
                        confidence: 0.9,
                    });
                }
            }
            return;
        }
        // Case 2: TaggedTemplateExpression — prisma.$queryRaw`SELECT ... ${expr}`
        if (node.type === 'TaggedTemplateExpression') {
            const tagged = node;
            if (!isORMTaggedTemplate(tagged))
                return;
            // Only flag if the template has dynamic expressions
            if (tagged.quasi.expressions.length > 0) {
                const line = node.loc.start.line;
                if (!reported.has(line)) {
                    reported.add(line);
                    findings.push({
                        type: 'SQL_INJECTION',
                        severity: 'critical',
                        line,
                        column: node.loc.start.column,
                        snippet: result.lines[line - 1]?.trim() ?? '',
                        message: 'ORM raw query (prisma.$queryRaw / $executeRaw) called with a dynamic template literal. ' +
                            'Use Prisma.sql tagged template or parameterized inputs to prevent SQL injection.',
                    });
                }
            }
        }
    });
    return findings;
}
//# sourceMappingURL=sql.js.map