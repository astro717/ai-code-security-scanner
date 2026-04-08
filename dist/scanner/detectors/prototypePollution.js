"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.detectPrototypePollution = detectPrototypePollution;
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
    // Object/Array literals with only static values are not considered dynamic sources
    if (node.type === 'ObjectExpression') {
        const obj = node;
        return obj.properties.some((p) => {
            if (p.type === 'SpreadElement')
                return isDynamic(p.argument);
            if (p.type === 'Property')
                return isDynamic(p.value);
            return false;
        });
    }
    return true;
}
/** Returns the identifier name of a node, or null if not an Identifier. */
function identName(node) {
    return node.type === 'Identifier' ? node.name : null;
}
function detectPrototypePollution(result) {
    const findings = [];
    (0, utils_1.walkNode)(result.ast, (node) => {
        // ── 1. obj.__proto__ = x ──────────────────────────────────────────────────
        if (node.type === 'AssignmentExpression') {
            const assign = node;
            if (assign.left.type === 'MemberExpression') {
                const mem = assign.left;
                const prop = mem.property;
                const propName = !mem.computed && prop.type === 'Identifier'
                    ? prop.name
                    : mem.computed && prop.type === 'Literal'
                        ? String(prop.value)
                        : null;
                if (propName === '__proto__') {
                    const line = node.loc.start.line;
                    findings.push({
                        type: 'PROTOTYPE_POLLUTION',
                        severity: 'critical',
                        line,
                        column: node.loc.start.column,
                        snippet: result.lines[line - 1]?.trim() ?? '',
                        message: 'Direct assignment to __proto__ can pollute the Object prototype and affect all objects in the application.',
                        confidence: 0.82,
                    });
                }
                // ── 2. obj.constructor.prototype = dynamicValue ───────────────────────
                if (propName === 'prototype' && mem.object.type === 'MemberExpression') {
                    const outerMem = mem.object;
                    const outerProp = outerMem.property;
                    const outerPropName = !outerMem.computed && outerProp.type === 'Identifier'
                        ? outerProp.name
                        : null;
                    if (outerPropName === 'constructor' && isDynamic(assign.right)) {
                        const line = node.loc.start.line;
                        findings.push({
                            type: 'PROTOTYPE_POLLUTION',
                            severity: 'critical',
                            line,
                            column: node.loc.start.column,
                            snippet: result.lines[line - 1]?.trim() ?? '',
                            message: 'Assignment to constructor.prototype with a dynamic value can pollute the prototype chain.',
                            confidence: 0.82,
                        });
                    }
                }
            }
        }
        // ── 3. Object.assign(target, src) / _.merge / _.extend where src is dynamic
        if (node.type === 'CallExpression') {
            const call = node;
            if (call.callee.type !== 'MemberExpression')
                return;
            const mem = call.callee;
            if (mem.computed)
                return;
            const obj = identName(mem.object);
            const fn = mem.property.type === 'Identifier'
                ? mem.property.name
                : null;
            if (!obj || !fn)
                return;
            const isMergeCall = (obj === 'Object' && fn === 'assign') ||
                (obj === '_' && (fn === 'merge' || fn === 'extend' || fn === 'mergeWith' || fn === 'defaultsDeep'));
            if (isMergeCall && call.arguments.length >= 2) {
                // Second argument (src) must be dynamic to be flagged
                const srcArg = call.arguments[1];
                if (srcArg.type !== 'SpreadElement' && isDynamic(srcArg)) {
                    const line = node.loc.start.line;
                    findings.push({
                        type: 'PROTOTYPE_POLLUTION',
                        severity: 'critical',
                        line,
                        column: node.loc.start.column,
                        snippet: result.lines[line - 1]?.trim() ?? '',
                        message: `${obj}.${fn}() called with a dynamic source object. If the source is user-controlled it can introduce __proto__ or constructor keys and pollute the prototype.`,
                        confidence: 0.82,
                    });
                }
            }
        }
    });
    return findings;
}
//# sourceMappingURL=prototypePollution.js.map