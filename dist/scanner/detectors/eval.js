"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.detectEval = detectEval;
const utils_1 = require("../utils");
function isStringLiteral(node) {
    return node.type === 'Literal' && typeof node.value === 'string';
}
function detectEval(result) {
    const findings = [];
    (0, utils_1.walkNode)(result.ast, (node) => {
        // eval(x) where x is not a string literal
        if (node.type === 'CallExpression') {
            const call = node;
            if (call.callee.type === 'Identifier' && call.callee.name === 'eval') {
                if (call.arguments.length > 0) {
                    const arg = call.arguments[0];
                    if (arg.type !== 'SpreadElement' && !isStringLiteral(arg)) {
                        const line = node.loc.start.line;
                        findings.push({
                            type: 'EVAL_INJECTION',
                            severity: 'high',
                            line,
                            column: node.loc.start.column,
                            snippet: result.lines[line - 1]?.trim() ?? '',
                            message: 'eval() called with a non-literal argument. This can execute arbitrary code.',
                            confidence: 0.92,
                        });
                    }
                }
            }
            // setTimeout(x) / setInterval(x) with string variable
            if (call.callee.type === 'Identifier' &&
                (call.callee.name === 'setTimeout' || call.callee.name === 'setInterval') &&
                call.arguments.length > 0) {
                const arg = call.arguments[0];
                if (arg.type !== 'SpreadElement' && isStringLiteral(arg) === false && arg.type !== 'ArrowFunctionExpression' && arg.type !== 'FunctionExpression') {
                    // Only flag if the first argument is a variable/identifier (string passed as arg)
                    if (arg.type === 'Identifier' || arg.type === 'TemplateLiteral' || arg.type === 'BinaryExpression') {
                        const line = node.loc.start.line;
                        findings.push({
                            type: 'EVAL_INJECTION',
                            severity: 'high',
                            line,
                            column: node.loc.start.column,
                            snippet: result.lines[line - 1]?.trim() ?? '',
                            message: `${call.callee.name}() called with a string variable — equivalent to eval().`,
                            confidence: 0.92,
                        });
                    }
                }
            }
        }
        // new Function(...) with non-literal args
        if (node.type === 'NewExpression') {
            const newExpr = node;
            if (newExpr.callee.type === 'Identifier' && newExpr.callee.name === 'Function') {
                const hasNonLiteralArg = newExpr.arguments.some((a) => a.type !== 'SpreadElement' && !isStringLiteral(a));
                if (hasNonLiteralArg) {
                    const line = node.loc.start.line;
                    findings.push({
                        type: 'EVAL_INJECTION',
                        severity: 'high',
                        line,
                        column: node.loc.start.column,
                        snippet: result.lines[line - 1]?.trim() ?? '',
                        message: 'new Function() with dynamic argument is equivalent to eval().',
                        confidence: 0.92,
                    });
                }
            }
        }
    });
    return findings;
}
//# sourceMappingURL=eval.js.map