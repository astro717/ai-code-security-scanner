import { TSESTree } from '@typescript-eslint/types';
import { ParseResult } from '../parser';
import { Finding } from '../reporter';
import { walkNode } from '../utils';

const WEAK_HASH_ALGORITHMS = new Set(['md5', 'md4', 'sha1', 'sha-1']);

/**
 * Detects usage of weak cryptographic hash algorithms:
 *   - crypto.createHash('md5')
 *   - crypto.createHash('sha1')
 *   - createHash('md5') after destructuring
 */
export function detectWeakCrypto(result: ParseResult): Finding[] {
  const findings: Finding[] = [];
  const reported = new Set<number>();

  walkNode(result.ast, (node) => {
    if (node.type !== 'CallExpression') return;
    const call = node as TSESTree.CallExpression;

    // Match createHash(...) — as bare call or crypto.createHash(...)
    let isCreateHash = false;

    if (call.callee.type === 'Identifier') {
      isCreateHash = (call.callee as TSESTree.Identifier).name === 'createHash';
    } else if (call.callee.type === 'MemberExpression' && !call.callee.computed) {
      const prop = (call.callee as TSESTree.MemberExpression).property;
      if (prop.type === 'Identifier') {
        isCreateHash = (prop as TSESTree.Identifier).name === 'createHash';
      }
    }

    if (!isCreateHash) return;
    if (call.arguments.length === 0) return;

    const firstArg = call.arguments[0];
    if (firstArg.type === 'SpreadElement') return;

    // Only flag if the algorithm is a known weak literal string
    if (
      (firstArg as TSESTree.Node).type === 'Literal' &&
      typeof ((firstArg as TSESTree.Literal).value) === 'string'
    ) {
      const alg = ((firstArg as TSESTree.Literal).value as string).toLowerCase();
      if (WEAK_HASH_ALGORITHMS.has(alg)) {
        const line = node.loc!.start.line;
        if (!reported.has(line)) {
          reported.add(line);
          findings.push({
            type: 'WEAK_CRYPTO',
            severity: 'high',
            line,
            column: node.loc!.start.column,
            snippet: result.lines[line - 1]?.trim() ?? '',
            message:
              `crypto.createHash('${alg}') uses a weak algorithm. ` +
              `MD5 and SHA-1 are cryptographically broken and must not be used for password hashing, ` +
              `digital signatures, or token generation. Use SHA-256 or SHA-3 instead. ` +
              `For passwords, use bcrypt, scrypt, or Argon2.`,
          });
        }
      }
    }
  });

  return findings;
}
