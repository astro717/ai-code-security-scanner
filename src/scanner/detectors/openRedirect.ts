import { TSESTree } from '@typescript-eslint/types';
import { ParseResult } from '../parser';
import { Finding } from '../reporter';
import { walkNode } from '../utils';

function isStaticString(node: TSESTree.Node): boolean {
  // A plain string literal is safe
  if (node.type === 'Literal') return true;
  // A template literal with no expressions is safe
  if (node.type === 'TemplateLiteral') {
    return (node as TSESTree.TemplateLiteral).expressions.length === 0;
  }
  return false;
}

/**
 * Detects calls to res.redirect() where the argument is not a static string.
 * Dynamic redirect targets can lead to open redirect vulnerabilities.
 */
export function detectOpenRedirect(result: ParseResult): Finding[] {
  const findings: Finding[] = [];

  walkNode(result.ast, (node) => {
    if (node.type !== 'CallExpression') return;

    const call = node as TSESTree.CallExpression;
    const callee = call.callee;

    // Match res.redirect(...) — MemberExpression where property is 'redirect'
    if (
      callee.type !== 'MemberExpression' ||
      callee.computed
    ) return;

    const property = (callee as TSESTree.MemberExpression).property;
    const propName = property.type === 'Identifier'
      ? (property as TSESTree.Identifier).name
      : '';

    if (propName !== 'redirect') return;

    // res.redirect([statusCode,] url)
    // Signatures: res.redirect(url) or res.redirect(status, url)
    const args = call.arguments;
    if (args.length === 0) return;

    // The URL argument is the last one (or only one if single arg)
    const urlArg = args[args.length - 1];
    if (urlArg.type === 'SpreadElement') return;

    if (!isStaticString(urlArg as TSESTree.Node)) {
      const line = node.loc!.start.line;
      findings.push({
        type: 'OPEN_REDIRECT',
        severity: 'medium',
        line,
        column: node.loc!.start.column,
        snippet: result.lines[line - 1]?.trim() ?? '',
        message:
          'res.redirect() called with a dynamic URL. Validate and whitelist redirect destinations to prevent open redirect attacks.',
                confidence: 0.72,
      });
    }
  });

  return findings;
}
