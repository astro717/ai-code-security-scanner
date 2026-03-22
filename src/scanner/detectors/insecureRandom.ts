import { TSESTree } from '@typescript-eslint/types';
import { ParseResult } from '../parser';
import { Finding } from '../reporter';
import { walkNode } from '../utils';

// Variable name patterns that suggest security-sensitive usage
const SECURITY_NAME_PATTERNS = [
  /token/i, /secret/i, /password/i, /passwd/i, /session/i, /csrf/i,
  /nonce/i, /salt/i, /\bkey\b/i, /\bkeys\b/i, /\bid\b/i, /\bids\b/i,
  /apikey/i, /api_key/i, /authtoken/i, /auth_token/i, /accesstoken/i,
  /reset/i, /verify/i, /otp/i, /pin\b/i,
];

function isSecuritySensitiveName(name: string): boolean {
  return SECURITY_NAME_PATTERNS.some((re) => re.test(name));
}

function isMathRandomCall(node: TSESTree.Node): boolean {
  if (node.type !== 'CallExpression') return false;
  const call = node as TSESTree.CallExpression;
  if (call.callee.type !== 'MemberExpression') return false;
  const callee = call.callee as TSESTree.MemberExpression;
  if (callee.computed) return false;
  const obj = callee.object;
  const prop = callee.property;
  return (
    obj.type === 'Identifier' && (obj as TSESTree.Identifier).name === 'Math' &&
    prop.type === 'Identifier' && (prop as TSESTree.Identifier).name === 'random'
  );
}

export function detectInsecureRandom(result: ParseResult): Finding[] {
  const findings: Finding[] = [];
  const reported = new Set<number>(); // avoid duplicate findings for same line

  walkNode(result.ast, (node) => {
    // 1. Variable assignment: const resetToken = Math.random() (or derived expression)
    if (node.type === 'VariableDeclarator') {
      const decl = node as TSESTree.VariableDeclarator;
      const idName =
        decl.id.type === 'Identifier' ? (decl.id as TSESTree.Identifier).name : '';
      if (idName && isSecuritySensitiveName(idName) && decl.init) {
        // Check if init or any sub-expression is Math.random()
        let foundRandom = false;
        walkNode(decl.init as TSESTree.Node, (child) => {
          if (isMathRandomCall(child)) foundRandom = true;
        });
        if (foundRandom) {
          const line = node.loc!.start.line;
          if (!reported.has(line)) {
            reported.add(line);
            findings.push({
              type: 'INSECURE_RANDOM',
              severity: 'medium',
              line,
              column: node.loc!.start.column,
              snippet: result.lines[line - 1]?.trim() ?? '',
              message: `Math.random() used to generate "${idName}". Math.random() is not cryptographically secure — use crypto.randomBytes() or crypto.getRandomValues() instead.`,
            });
          }
        }
      }
    }

    // 2. Assignment expression: obj.sessionToken = Math.random() * ...
    if (node.type === 'AssignmentExpression') {
      const assign = node as TSESTree.AssignmentExpression;
      const left = assign.left;
      let assignedName = '';
      if (left.type === 'Identifier') {
        assignedName = (left as TSESTree.Identifier).name;
      } else if (left.type === 'MemberExpression' && !(left as TSESTree.MemberExpression).computed) {
        const prop = (left as TSESTree.MemberExpression).property;
        assignedName = prop.type === 'Identifier' ? (prop as TSESTree.Identifier).name : '';
      }
      if (assignedName && isSecuritySensitiveName(assignedName)) {
        let foundRandom = false;
        walkNode(assign.right as TSESTree.Node, (child) => {
          if (isMathRandomCall(child)) foundRandom = true;
        });
        if (foundRandom) {
          const line = node.loc!.start.line;
          if (!reported.has(line)) {
            reported.add(line);
            findings.push({
              type: 'INSECURE_RANDOM',
              severity: 'medium',
              line,
              column: node.loc!.start.column,
              snippet: result.lines[line - 1]?.trim() ?? '',
              message: `Math.random() assigned to "${assignedName}". Math.random() is not cryptographically secure — use crypto.randomBytes() or crypto.getRandomValues() instead.`,
            });
          }
        }
      }
    }

    // 3. Math.random() passed directly to btoa()
    if (node.type === 'CallExpression') {
      const call = node as TSESTree.CallExpression;
      const callee = call.callee;
      const fnName =
        callee.type === 'Identifier' ? (callee as TSESTree.Identifier).name :
        (callee.type === 'MemberExpression' && !(callee as TSESTree.MemberExpression).computed)
          ? ((callee as TSESTree.MemberExpression).property.type === 'Identifier'
              ? ((callee as TSESTree.MemberExpression).property as TSESTree.Identifier).name
              : '')
          : '';

      if (fnName === 'btoa' || fnName === 'toString' || fnName === 'encode') {
        for (const arg of call.arguments) {
          if (arg.type === 'SpreadElement') continue;
          let foundRandom = false;
          walkNode(arg as TSESTree.Node, (child) => {
            if (isMathRandomCall(child)) foundRandom = true;
          });
          if (foundRandom) {
            const line = node.loc!.start.line;
            if (!reported.has(line)) {
              reported.add(line);
              findings.push({
                type: 'INSECURE_RANDOM',
                severity: 'medium',
                line,
                column: node.loc!.start.column,
                snippet: result.lines[line - 1]?.trim() ?? '',
                message: `Math.random() value encoded via ${fnName}(). This is not cryptographically secure. Use crypto.randomBytes() for tokens and credentials.`,
              });
            }
          }
        }
      }
    }

    // 4. Math.random() concatenated in a string that's assigned to a security-sensitive var
    // (Covered by patterns 1 & 2 via the recursive walkNode on the right-hand side)
  });

  return findings;
}
