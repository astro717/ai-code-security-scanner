import { TSESTree } from '@typescript-eslint/types';
import { ParseResult } from '../parser';
import { Finding } from '../reporter';
import { walkNode } from '../utils';

function isLiteral(node: TSESTree.Node): boolean {
  return node.type === 'Literal';
}

function isDynamic(node: TSESTree.Node): boolean {
  if (isLiteral(node)) return false;
  if (node.type === 'TemplateLiteral') {
    return (node as TSESTree.TemplateLiteral).expressions.length > 0;
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

function getCallName(call: TSESTree.CallExpression): { module: string; fn: string } | null {
  const callee = call.callee;
  if (callee.type === 'MemberExpression' && !callee.computed) {
    const obj = callee.object;
    const prop = callee.property;
    const objName = obj.type === 'Identifier' ? (obj as TSESTree.Identifier).name : '';
    const fnName = prop.type === 'Identifier' ? (prop as TSESTree.Identifier).name : '';
    return { module: objName, fn: fnName };
  }
  return null;
}

export function detectPathTraversal(result: ParseResult): Finding[] {
  const findings: Finding[] = [];

  // Track variables imported/required from 'fs' and 'path'
  const fsAliases = new Set<string>(['fs']);
  const pathAliases = new Set<string>(['path']);

  walkNode(result.ast, (node) => {
    // Collect: import fs from 'fs' / import * as fs from 'fs'
    if (node.type === 'ImportDeclaration') {
      const imp = node as TSESTree.ImportDeclaration;
      const src = (imp.source as TSESTree.Literal).value as string;
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
    if (
      node.type === 'VariableDeclarator' &&
      (node as TSESTree.VariableDeclarator).init?.type === 'CallExpression'
    ) {
      const decl = node as TSESTree.VariableDeclarator;
      const init = decl.init as TSESTree.CallExpression;
      if (
        init.callee.type === 'Identifier' &&
        (init.callee as TSESTree.Identifier).name === 'require' &&
        init.arguments.length > 0 &&
        init.arguments[0].type === 'Literal'
      ) {
        const src = (init.arguments[0] as TSESTree.Literal).value as string;
        if (src === 'fs' || src === 'fs/promises' || src === 'node:fs') {
          if (decl.id.type === 'Identifier') fsAliases.add((decl.id as TSESTree.Identifier).name);
        }
        if (src === 'path' || src === 'node:path') {
          if (decl.id.type === 'Identifier') pathAliases.add((decl.id as TSESTree.Identifier).name);
        }
      }
    }

    if (node.type !== 'CallExpression') return;
    const call = node as TSESTree.CallExpression;
    const info = getCallName(call);
    if (!info) return;

    // 1. fs.readFile / fs.readFileSync with dynamic path
    if (fsAliases.has(info.module) && FS_PATH_FUNCTIONS.has(info.fn)) {
      if (call.arguments.length > 0) {
        const firstArg = call.arguments[0];
        if (firstArg.type !== 'SpreadElement' && isDynamic(firstArg as TSESTree.Node)) {
          const line = node.loc!.start.line;
          findings.push({
            type: 'PATH_TRAVERSAL',
            severity: 'high',
            line,
            column: node.loc!.start.column,
            snippet: result.lines[line - 1]?.trim() ?? '',
            message: `${info.fn}() called with dynamic path derived from user input. Validate and sanitize paths to prevent directory traversal (../../../etc/passwd).`,
          });
        }
      }
    }

    // 2. path.join(...args) where any argument is dynamic
    if (pathAliases.has(info.module) && (info.fn === 'join' || info.fn === 'resolve')) {
      const hasDynamicArg = call.arguments.some(
        (arg) => arg.type !== 'SpreadElement' && isDynamic(arg as TSESTree.Node),
      );
      if (hasDynamicArg) {
        const line = node.loc!.start.line;
        findings.push({
          type: 'PATH_TRAVERSAL',
          severity: 'high',
          line,
          column: node.loc!.start.column,
          snippet: result.lines[line - 1]?.trim() ?? '',
          message: `path.${info.fn}() called with dynamic argument. User-controlled path segments can escape the intended directory.`,
        });
      }
    }
  });

  return findings;
}
