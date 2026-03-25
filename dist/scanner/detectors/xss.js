"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.detectXSS = detectXSS;
const utils_1 = require("../utils");
function isLiteral(node) {
    return node.type === 'Literal';
}
function isDynamic(node) {
    if (isLiteral(node))
        return false;
    if (node.type === 'TemplateLiteral') {
        return node.expressions.length > 0;
    }
    return true;
}
function detectXSS(result) {
    const findings = [];
    (0, utils_1.walkNode)(result.ast, (node) => {
        // 1. dangerouslySetInnerHTML={{ __html: dynamicValue }}
        if (node.type === 'JSXAttribute') {
            const attr = node;
            const nameNode = attr.name;
            const attrName = nameNode.type === 'JSXIdentifier' ? nameNode.name : '';
            if (attrName === 'dangerouslySetInnerHTML' && attr.value) {
                // value is JSXExpressionContainer
                if (attr.value.type === 'JSXExpressionContainer') {
                    const expr = attr.value.expression;
                    if (expr.type !== 'JSXEmptyExpression') {
                        // Check if __html property is dynamic
                        let hasDynamicHtml = false;
                        if (expr.type === 'ObjectExpression') {
                            for (const prop of expr.properties) {
                                if (prop.type === 'Property') {
                                    const p = prop;
                                    const keyName = p.key.type === 'Identifier' ? p.key.name :
                                        p.key.type === 'Literal' ? String(p.key.value) : '';
                                    if (keyName === '__html' && isDynamic(p.value)) {
                                        hasDynamicHtml = true;
                                    }
                                }
                            }
                        }
                        else {
                            // dangerouslySetInnerHTML={variable} — treat as dynamic
                            hasDynamicHtml = true;
                        }
                        if (hasDynamicHtml) {
                            const line = node.loc.start.line;
                            findings.push({
                                type: 'XSS',
                                severity: 'critical',
                                line,
                                column: node.loc.start.column,
                                snippet: result.lines[line - 1]?.trim() ?? '',
                                message: 'dangerouslySetInnerHTML with dynamic value. Unsanitized HTML leads to XSS.',
                            });
                        }
                    }
                }
            }
        }
        // 2. element.innerHTML = variable  (AssignmentExpression)
        if (node.type === 'AssignmentExpression') {
            const assign = node;
            if (assign.left.type === 'MemberExpression' &&
                !assign.left.computed) {
                const prop = assign.left.property;
                const propName = prop.type === 'Identifier' ? prop.name : '';
                if (propName === 'innerHTML' || propName === 'outerHTML') {
                    if (isDynamic(assign.right)) {
                        const line = node.loc.start.line;
                        findings.push({
                            type: 'XSS',
                            severity: 'critical',
                            line,
                            column: node.loc.start.column,
                            snippet: result.lines[line - 1]?.trim() ?? '',
                            message: `Assignment to .${propName} with dynamic value. Use textContent or sanitize the HTML first.`,
                        });
                    }
                }
            }
        }
        // 3. document.write(variable) / document.writeln(variable)
        if (node.type === 'CallExpression') {
            const call = node;
            if (call.callee.type === 'MemberExpression' &&
                !call.callee.computed) {
                const obj = call.callee.object;
                const prop = call.callee.property;
                const objName = obj.type === 'Identifier' ? obj.name : '';
                const propName = prop.type === 'Identifier' ? prop.name : '';
                if (objName === 'document' && (propName === 'write' || propName === 'writeln')) {
                    if (call.arguments.length > 0) {
                        const firstArg = call.arguments[0];
                        if (firstArg.type !== 'SpreadElement' && isDynamic(firstArg)) {
                            const line = node.loc.start.line;
                            findings.push({
                                type: 'XSS',
                                severity: 'critical',
                                line,
                                column: node.loc.start.column,
                                snippet: result.lines[line - 1]?.trim() ?? '',
                                message: `document.${propName}() called with dynamic value. Avoid document.write() — it enables XSS.`,
                            });
                        }
                    }
                }
            }
        }
    });
    return findings;
}
//# sourceMappingURL=xss.js.map