import { TSESTree } from '@typescript-eslint/types';
import { ParseResult } from '../parser';
import { Finding } from '../reporter';
import { walkNode } from '../utils';

function isStaticStringOrRegex(node: TSESTree.Node): boolean {
  if (node.type === 'Literal') return true; // string, regex literal — static
  if (node.type === 'TemplateLiteral') {
    return (node as TSESTree.TemplateLiteral).expressions.length === 0;
  }
  return false;
}

/**
 * Detects ReDoS (Regex Denial of Service) via dynamic RegExp construction:
 *   - new RegExp(userInput)
 *   - new RegExp(userInput, flags)
 * where the pattern argument is not a static string/regex literal.
 */
export function detectReDoS(result: ParseResult): Finding[] {
  const findings: Finding[] = [];
  const reported = new Set<number>();

  walkNode(result.ast, (node) => {
    // Match: new RegExp(...)
    if (node.type !== 'NewExpression') return;
    const newExpr = node as TSESTree.NewExpression;

    if (
      newExpr.callee.type !== 'Identifier' ||
      (newExpr.callee as TSESTree.Identifier).name !== 'RegExp'
    ) return;

    if (newExpr.arguments.length === 0) return;

    const firstArg = newExpr.arguments[0];
    if (firstArg.type === 'SpreadElement') return;

    // Only flag if the pattern is dynamic (not a static literal)
    if (!isStaticStringOrRegex(firstArg as TSESTree.Node)) {
      const line = node.loc!.start.line;
      if (!reported.has(line)) {
        reported.add(line);
        findings.push({
          type: 'REDOS',
          severity: 'medium',
          line,
          column: node.loc!.start.column,
          snippet: result.lines[line - 1]?.trim() ?? '',
          message:
            'new RegExp() called with a dynamic pattern. If the pattern originates from user input, ' +
            'an attacker can craft a catastrophically backtracking regex causing denial of service (ReDoS). ' +
            'Validate and sanitize the pattern, or use a safe regex library before constructing RegExp dynamically.',
        });
      }
    }
  });

  return findings;
}
