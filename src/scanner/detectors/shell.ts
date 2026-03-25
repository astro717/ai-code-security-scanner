import { TSESTree } from '@typescript-eslint/types';
import { ParseResult } from '../parser';
import { Finding } from '../reporter';
import { getSnippet } from '../utils';

// execFile/execFileSync and spawn/spawnSync are intentionally excluded: they do
// NOT invoke a shell — they take a file path and an args array directly, so the
// risk profile is COMMAND_INJECTION (handled by commandInjection.ts), not
// SHELL_INJECTION. Including them here would produce false positives with the
// wrong vulnerability type.
const SHELL_FUNCTIONS = new Set(['exec', 'execSync']);

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

function isSimpleStringLiteral(node: TSESTree.Node): boolean {
  return node.type === 'Literal' && typeof (node as TSESTree.Literal).value === 'string';
}

function isShellCall(callee: TSESTree.LeftHandSideExpression): string | null {
  if (callee.type === 'Identifier' && SHELL_FUNCTIONS.has(callee.name)) {
    return callee.name;
  }
  if (callee.type === 'MemberExpression') {
    const prop = callee.property;
    if (prop.type === 'Identifier' && SHELL_FUNCTIONS.has(prop.name)) {
      return prop.name;
    }
  }
  return null;
}

export function detectShellInjection(result: ParseResult): Finding[] {
  const findings: Finding[] = [];

  walkNode(result.ast, (node) => {
    if (node.type !== 'CallExpression') return;
    const call = node as TSESTree.CallExpression;

    const fnName = isShellCall(call.callee as TSESTree.LeftHandSideExpression);
    if (!fnName) return;
    if (call.arguments.length === 0) return;

    const firstArg = call.arguments[0];
    if (firstArg.type === 'SpreadElement') return;

    // exec/execSync: first arg should be a plain string literal
    if (!isSimpleStringLiteral(firstArg)) {
      const line = node.loc!.start.line;
      const snippet = getSnippet(result, line);
      findings.push({
        type: 'SHELL_INJECTION',
        severity: 'high',
        line,
        column: node.loc!.start.column,
        snippet,
        message: `${fnName}() called with a non-literal argument. Unsanitized input may lead to shell injection.`,
      });
    }
  });

  return findings;
}
