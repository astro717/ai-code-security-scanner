"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.detectPathTraversal = detectPathTraversal;
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
// FS functions that take a file path as their first argument
const FS_PATH_FUNCTIONS = new Set([
    'readFile', 'readFileSync',
    'writeFile', 'writeFileSync',
    'appendFile', 'appendFileSync',
    'unlink', 'unlinkSync',
    'stat', 'statSync',
    'lstat', 'lstatSync',
    'access', 'accessSync',
    'open', 'openSync',
    'createReadStream', 'createWriteStream',
]);
function getCallName(call) {
    const callee = call.callee;
    if (callee.type === 'MemberExpression' && !callee.computed) {
        const obj = callee.object;
        const prop = callee.property;
        const objName = obj.type === 'Identifier' ? obj.name : '';
        const fnName = prop.type === 'Identifier' ? prop.name : '';
        return { module: objName, fn: fnName };
    }
    return null;
}
function detectPathTraversal(result) {
    const findings = [];
    // Track variables imported/required from 'fs' and 'path'
    const fsAliases = new Set(['fs']);
    const pathAliases = new Set(['path']);
    (0, utils_1.walkNode)(result.ast, (node) => {
        // Collect: import fs from 'fs' / import * as fs from 'fs'
        if (node.type === 'ImportDeclaration') {
            const imp = node;
            const src = imp.source.value;
            if (src === 'fs' || src === 'fs/promises' || src === 'node:fs') {
                for (const spec of imp.specifiers) {
                    if (spec.type === 'ImportDefaultSpecifier' || spec.type === 'ImportNamespaceSpecifier') {
                        fsAliases.add(spec.local.name);
                    }
                }
            }
            if (src === 'path' || src === 'node:path') {
                for (const spec of imp.specifiers) {
                    if (spec.type === 'ImportDefaultSpecifier' || spec.type === 'ImportNamespaceSpecifier') {
                        pathAliases.add(spec.local.name);
                    }
                }
            }
        }
        // Collect: const fs = require('fs') / const { readFile } = require('fs')
        if (node.type === 'VariableDeclarator' &&
            node.init?.type === 'CallExpression') {
            const decl = node;
            const init = decl.init;
            if (init.callee.type === 'Identifier' &&
                init.callee.name === 'require' &&
                init.arguments.length > 0 &&
                init.arguments[0].type === 'Literal') {
                const src = init.arguments[0].value;
                if (src === 'fs' || src === 'fs/promises' || src === 'node:fs') {
                    if (decl.id.type === 'Identifier')
                        fsAliases.add(decl.id.name);
                }
                if (src === 'path' || src === 'node:path') {
                    if (decl.id.type === 'Identifier')
                        pathAliases.add(decl.id.name);
                }
            }
        }
        if (node.type !== 'CallExpression')
            return;
        const call = node;
        const info = getCallName(call);
        if (!info)
            return;
        // 1. fs.readFile / fs.readFileSync with dynamic path
        if (fsAliases.has(info.module) && FS_PATH_FUNCTIONS.has(info.fn)) {
            if (call.arguments.length > 0) {
                const firstArg = call.arguments[0];
                if (firstArg.type !== 'SpreadElement' && isDynamic(firstArg)) {
                    const line = node.loc.start.line;
                    findings.push({
                        type: 'PATH_TRAVERSAL',
                        severity: 'high',
                        line,
                        column: node.loc.start.column,
                        snippet: result.lines[line - 1]?.trim() ?? '',
                        message: `${info.fn}() called with dynamic path derived from user input. Validate and sanitize paths to prevent directory traversal (../../../etc/passwd).`,
                        confidence: 0.85,
                    });
                }
            }
        }
        // 2. path.join(...args) where any argument is dynamic
        if (pathAliases.has(info.module) && (info.fn === 'join' || info.fn === 'resolve')) {
            const hasDynamicArg = call.arguments.some((arg) => arg.type !== 'SpreadElement' && isDynamic(arg));
            if (hasDynamicArg) {
                const line = node.loc.start.line;
                findings.push({
                    type: 'PATH_TRAVERSAL',
                    severity: 'high',
                    line,
                    column: node.loc.start.column,
                    snippet: result.lines[line - 1]?.trim() ?? '',
                    message: `path.${info.fn}() called with dynamic argument. User-controlled path segments can escape the intended directory.`,
                    confidence: 0.85,
                });
            }
        }
    });
    return findings;
}
//# sourceMappingURL=pathTraversal.js.map