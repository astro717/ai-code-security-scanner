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

function isStringValue(node: TSESTree.Node, value: string): boolean {
  return node.type === 'Literal' && (node as TSESTree.Literal).value === value;
}

/**
 * Looks inside an options object for { algorithms: [...] } or { algorithm: '...' }
 * Returns true if 'none' algorithm is explicitly set.
 */
function hasNoneAlgorithm(optionsNode: TSESTree.Node): boolean {
  if (optionsNode.type !== 'ObjectExpression') return false;
  const obj = optionsNode as TSESTree.ObjectExpression;

  for (const prop of obj.properties) {
    if (prop.type !== 'Property') continue;
    const p = prop as TSESTree.Property;

    const keyName =
      p.key.type === 'Identifier'
        ? (p.key as TSESTree.Identifier).name
        : p.key.type === 'Literal'
          ? String((p.key as TSESTree.Literal).value)
          : null;

    if (!keyName) continue;

    if (keyName === 'algorithm' && isStringValue(p.value as TSESTree.Node, 'none')) {
      return true;
    }

    if (keyName === 'algorithms' && (p.value as TSESTree.Node).type === 'ArrayExpression') {
      const arr = p.value as TSESTree.ArrayExpression;
      if (arr.elements.some((el) => el && isStringValue(el as TSESTree.Node, 'none'))) {
        return true;
      }
    }
  }
  return false;
}

/**
 * Detects JWT none-algorithm vulnerability:
 *   1. jwt.verify(token, secret) called WITHOUT an options object specifying algorithms
 *      (missing algorithms whitelist allows 'none' algorithm in older jsonwebtoken versions)
 *   2. jwt.verify(token, secret, { algorithms: ['none'] }) — explicitly set to none
 *   3. jwt.decode(token, { complete: true }) — jwt.decode bypasses signature verification entirely
 */
export function detectJWTNoneAlgorithm(result: ParseResult): Finding[] {
  const findings: Finding[] = [];
  const reported = new Set<number>();

  walkNode(result.ast, (node) => {
    if (node.type !== 'CallExpression') return;
    const call = node as TSESTree.CallExpression;

    if (call.callee.type !== 'MemberExpression') return;
    const member = call.callee as TSESTree.MemberExpression;
    if (member.property.type !== 'Identifier') return;

    const methodName = (member.property as TSESTree.Identifier).name;
    const line = node.loc!.start.line;
    if (reported.has(line)) return;

    // Detect jwt.verify() with no options or no algorithms whitelist
    if (methodName === 'verify') {
      const args = call.arguments;

      // jwt.verify(token, secret) — no options at all (missing algorithms whitelist)
      if (args.length < 3) {
        reported.add(line);
        findings.push({
          type: 'JWT_NONE_ALGORITHM',
          severity: 'high',
          line,
          column: node.loc!.start.column,
          snippet: result.lines[line - 1]?.trim() ?? '',
          message:
            'jwt.verify() called without an explicit algorithms whitelist. ' +
            'In vulnerable versions of jsonwebtoken this allows the "none" algorithm, ' +
            'letting attackers forge tokens without a signature. ' +
            'Always pass { algorithms: [\'RS256\'] } or your expected algorithm.',
        });
        return;
      }

      // jwt.verify(token, secret, options) — check if algorithms: ['none']
      const optionsArg = args[2];
      if (optionsArg && optionsArg.type !== 'SpreadElement' && hasNoneAlgorithm(optionsArg as TSESTree.Node)) {
        reported.add(line);
        findings.push({
          type: 'JWT_NONE_ALGORITHM',
          severity: 'critical',
          line,
          column: node.loc!.start.column,
          snippet: result.lines[line - 1]?.trim() ?? '',
          message:
            'jwt.verify() called with algorithm set to "none". ' +
            'The "none" algorithm disables signature verification entirely, ' +
            'allowing any unsigned token to be accepted. Remove "none" from the algorithms list.',
        });
      }
    }

    // Detect jwt.decode() — never verifies signature
    if (methodName === 'decode') {
      reported.add(line);
      findings.push({
        type: 'JWT_DECODE_NO_VERIFY',
        severity: 'high',
        line,
        column: node.loc!.start.column,
        snippet: result.lines[line - 1]?.trim() ?? '',
        message:
          'jwt.decode() does not verify the token signature. ' +
          'Use jwt.verify() with an explicit algorithms whitelist to authenticate tokens. ' +
          'Only use jwt.decode() for reading claims from already-verified tokens.',
      });
    }
  });

  return findings;
}
