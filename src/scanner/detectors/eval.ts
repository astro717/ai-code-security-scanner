import { TSESTree } from '@typescript-eslint/types';
import { ParseResult } from '../parser';
import { Finding } from '../reporter';

function walkNode(node: TSESTree.Node, callback: (n: TSESTree.Node) => void): void {
  callback(node);
  for (const key of Object.keys(node)) {
    const child = (node as unknown as Record<string, unknown>)[key];
    if (child && typeof child === 'object') {
      if (Array.isArray(child)) {
        child.forEach((c) => { if (c && typeof c === 'object' && 'type' in c) walkNode(c as TSESTree.Node, callback); });
      } else if ('type' in child) {
        walkNode(child as TSESTree.Node, callback);
      }
    }
  }
}

function isStringLiteral(node: TSESTree.Node): boolean {
  return node.type === 'Literal' && typeof (node as TSESTree.Literal).value === 'string';
}

export function detectEval(result: ParseResult): Finding[] {
  const findings: Finding[] = [];

  walkNode(result.ast, (node) => {
    // eval(x) where x is not a string literal
    if (node.type === 'CallExpression') {
      const call = node as TSESTree.CallExpression;

      if (call.callee.type === 'Identifier' && call.callee.name === 'eval') {
        if (call.arguments.length > 0) {
          const arg = call.arguments[0];
          if (arg.type !== 'SpreadElement' && !isStringLiteral(arg)) {
            const line = node.loc!.start.line;
            findings.push({
              type: 'EVAL_INJECTION',
              severity: 'high',
              line,
              column: node.loc!.start.column,
              snippet: result.lines[line - 1]?.trim() ?? '',
              message: 'eval() called with a non-literal argument. This can execute arbitrary code.',
            });
          }
        }
      }

      // setTimeout(x) / setInterval(x) with string variable
      if (
        call.callee.type === 'Identifier' &&
        (call.callee.name === 'setTimeout' || call.callee.name === 'setInterval') &&
        call.arguments.length > 0
      ) {
        const arg = call.arguments[0];
        if (arg.type !== 'SpreadElement' && isStringLiteral(arg) === false && arg.type !== 'ArrowFunctionExpression' && arg.type !== 'FunctionExpression') {
          // Only flag if the first argument is a variable/identifier (string passed as arg)
          if (arg.type === 'Identifier' || arg.type === 'TemplateLiteral' || arg.type === 'BinaryExpression') {
            const line = node.loc!.start.line;
            findings.push({
              type: 'EVAL_INJECTION',
              severity: 'high',
              line,
              column: node.loc!.start.column,
              snippet: result.lines[line - 1]?.trim() ?? '',
              message: `${call.callee.name}() called with a string variable — equivalent to eval().`,
            });
          }
        }
      }
    }

    // new Function(...) with non-literal args
    if (node.type === 'NewExpression') {
      const newExpr = node as TSESTree.NewExpression;
      if (newExpr.callee.type === 'Identifier' && newExpr.callee.name === 'Function') {
        const hasNonLiteralArg = newExpr.arguments.some(
          (a) => a.type !== 'SpreadElement' && !isStringLiteral(a)
        );
        if (hasNonLiteralArg) {
          const line = node.loc!.start.line;
          findings.push({
            type: 'EVAL_INJECTION',
            severity: 'high',
            line,
            column: node.loc!.start.column,
            snippet: result.lines[line - 1]?.trim() ?? '',
            message: 'new Function() with dynamic argument is equivalent to eval().',
          });
        }
      }
    }
  });

  return findings;
}
