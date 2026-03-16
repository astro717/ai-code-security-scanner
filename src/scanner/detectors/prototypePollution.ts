import { TSESTree } from '@typescript-eslint/types';
import { ParseResult } from '../parser';
import { Finding } from '../reporter';

function walkNode(node: TSESTree.Node, callback: (n: TSESTree.Node) => void): void {
  callback(node);
  for (const key of Object.keys(node)) {
    const child = (node as unknown as Record<string, unknown>)[key];
    if (child && typeof child === 'object') {
      if (Array.isArray(child)) {
        child.forEach((c) => {
          if (c && typeof c === 'object' && 'type' in c) walkNode(c as TSESTree.Node, callback);
        });
      } else if ('type' in child) {
        walkNode(child as TSESTree.Node, callback);
      }
    }
  }
}

function isLiteral(node: TSESTree.Node): boolean {
  return node.type === 'Literal';
}

function isDynamic(node: TSESTree.Node): boolean {
  if (isLiteral(node)) return false;
  if (node.type === 'TemplateLiteral') {
    return (node as TSESTree.TemplateLiteral).expressions.length > 0;
  }
  // Object/Array literals with only static values are not considered dynamic sources
  if (node.type === 'ObjectExpression') {
    const obj = node as TSESTree.ObjectExpression;
    return obj.properties.some((p) => {
      if (p.type === 'SpreadElement') return isDynamic(p.argument as TSESTree.Node);
      if (p.type === 'Property') return isDynamic((p as TSESTree.Property).value as TSESTree.Node);
      return false;
    });
  }
  return true;
}

/** Returns the identifier name of a node, or null if not an Identifier. */
function identName(node: TSESTree.Node): string | null {
  return node.type === 'Identifier' ? (node as TSESTree.Identifier).name : null;
}

export function detectPrototypePollution(result: ParseResult): Finding[] {
  const findings: Finding[] = [];

  walkNode(result.ast, (node) => {
    // ── 1. obj.__proto__ = x ──────────────────────────────────────────────────
    if (node.type === 'AssignmentExpression') {
      const assign = node as TSESTree.AssignmentExpression;
      if (assign.left.type === 'MemberExpression') {
        const mem = assign.left as TSESTree.MemberExpression;
        const prop = mem.property;
        const propName = !mem.computed && prop.type === 'Identifier'
          ? (prop as TSESTree.Identifier).name
          : mem.computed && prop.type === 'Literal'
            ? String((prop as TSESTree.Literal).value)
            : null;

        if (propName === '__proto__') {
          const line = node.loc!.start.line;
          findings.push({
            type: 'PROTOTYPE_POLLUTION',
            severity: 'critical',
            line,
            column: node.loc!.start.column,
            snippet: result.lines[line - 1]?.trim() ?? '',
            message:
              'Direct assignment to __proto__ can pollute the Object prototype and affect all objects in the application.',
          });
        }

        // ── 2. obj.constructor.prototype = dynamicValue ───────────────────────
        if (propName === 'prototype' && mem.object.type === 'MemberExpression') {
          const outerMem = mem.object as TSESTree.MemberExpression;
          const outerProp = outerMem.property;
          const outerPropName =
            !outerMem.computed && outerProp.type === 'Identifier'
              ? (outerProp as TSESTree.Identifier).name
              : null;
          if (outerPropName === 'constructor' && isDynamic(assign.right)) {
            const line = node.loc!.start.line;
            findings.push({
              type: 'PROTOTYPE_POLLUTION',
              severity: 'critical',
              line,
              column: node.loc!.start.column,
              snippet: result.lines[line - 1]?.trim() ?? '',
              message:
                'Assignment to constructor.prototype with a dynamic value can pollute the prototype chain.',
            });
          }
        }
      }
    }

    // ── 3. Object.assign(target, src) / _.merge / _.extend where src is dynamic
    if (node.type === 'CallExpression') {
      const call = node as TSESTree.CallExpression;
      if (call.callee.type !== 'MemberExpression') return;
      const mem = call.callee as TSESTree.MemberExpression;
      if (mem.computed) return;

      const obj = identName(mem.object);
      const fn = mem.property.type === 'Identifier'
        ? (mem.property as TSESTree.Identifier).name
        : null;

      if (!obj || !fn) return;

      const isMergeCall =
        (obj === 'Object' && fn === 'assign') ||
        (obj === '_' && (fn === 'merge' || fn === 'extend' || fn === 'mergeWith' || fn === 'defaultsDeep'));

      if (isMergeCall && call.arguments.length >= 2) {
        // Second argument (src) must be dynamic to be flagged
        const srcArg = call.arguments[1];
        if (srcArg.type !== 'SpreadElement' && isDynamic(srcArg as TSESTree.Node)) {
          const line = node.loc!.start.line;
          findings.push({
            type: 'PROTOTYPE_POLLUTION',
            severity: 'critical',
            line,
            column: node.loc!.start.column,
            snippet: result.lines[line - 1]?.trim() ?? '',
            message: `${obj}.${fn}() called with a dynamic source object. If the source is user-controlled it can introduce __proto__ or constructor keys and pollute the prototype.`,
          });
        }
      }
    }
  });

  return findings;
}
