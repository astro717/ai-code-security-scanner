"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.detectOpenRedirect = detectOpenRedirect;
const utils_1 = require("../utils");
function isStaticString(node) {
    // A plain string literal is safe
    if (node.type === 'Literal')
        return true;
    // A template literal with no expressions is safe
    if (node.type === 'TemplateLiteral') {
        return node.expressions.length === 0;
    }
    return false;
}
/**
 * Detects calls to res.redirect() where the argument is not a static string.
 * Dynamic redirect targets can lead to open redirect vulnerabilities.
 */
function detectOpenRedirect(result) {
    const findings = [];
    (0, utils_1.walkNode)(result.ast, (node) => {
        if (node.type !== 'CallExpression')
            return;
        const call = node;
        const callee = call.callee;
        // Match res.redirect(...) — MemberExpression where property is 'redirect'
        if (callee.type !== 'MemberExpression' ||
            callee.computed)
            return;
        const property = callee.property;
        const propName = property.type === 'Identifier'
            ? property.name
            : '';
        if (propName !== 'redirect')
            return;
        // res.redirect([statusCode,] url)
        // Signatures: res.redirect(url) or res.redirect(status, url)
        const args = call.arguments;
        if (args.length === 0)
            return;
        // The URL argument is the last one (or only one if single arg)
        const urlArg = args[args.length - 1];
        if (urlArg.type === 'SpreadElement')
            return;
        if (!isStaticString(urlArg)) {
            const line = node.loc.start.line;
            findings.push({
                type: 'OPEN_REDIRECT',
                severity: 'medium',
                line,
                column: node.loc.start.column,
                snippet: result.lines[line - 1]?.trim() ?? '',
                message: 'res.redirect() called with a dynamic URL. Validate and whitelist redirect destinations to prevent open redirect attacks.',
            });
        }
    });
    return findings;
}
//# sourceMappingURL=openRedirect.js.map