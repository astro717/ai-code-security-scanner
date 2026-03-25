import { TSESTree } from '@typescript-eslint/types';
import { ParseResult } from '../parser';
import { Finding } from '../reporter';
import { walkNode, getSnippet } from '../utils';

/**
 * Detects command injection via spawn()/spawnSync() where the first argument
 * (the command to execute) is a variable or template literal with expressions
 * rather than a static string literal.
 *
 * This is distinct from SHELL_INJECTION (exec/execSync with dynamic strings)
 * because spawn does NOT invoke a shell by default — yet a dynamic command
 * name still allows an attacker to execute arbitrary programs.
 *
 * Examples flagged:
 *   spawn(userCmd, args)
 *   spawn(`${req.body.tool}`, args)
 *   spawnSync(cmd, ['-r', file])
 *   child_process.spawn(commandVar, [])
 */

const SPAWN_FUNCTIONS = new Set(['spawn', 'spawnSync']);

/**
 * Returns true only if the node is a static string literal with no dynamic
 * parts — i.e. the command is fully hardcoded and cannot be influenced by
 * external input.
 */
function isStaticCommand(node: TSESTree.Node): boolean {
  if (node.type === 'Literal' && typeof (node as TSESTree.Literal).value === 'string') {
    return true;
  }
  // A template literal with zero expressions is still static: `ls`
  if (node.type === 'TemplateLiteral') {
    return (node as TSESTree.TemplateLiteral).expressions.length === 0;
  }
  return false;
}

function isSpawnCall(callee: TSESTree.LeftHandSideExpression): string | null {
  // spawn(...) / spawnSync(...)
  if (callee.type === 'Identifier' && SPAWN_FUNCTIONS.has((callee as TSESTree.Identifier).name)) {
    return (callee as TSESTree.Identifier).name;
  }
  // child_process.spawn(...) / cp.spawnSync(...) / require('child_process').spawn(...)
  if (callee.type === 'MemberExpression' && !(callee as TSESTree.MemberExpression).computed) {
    const prop = (callee as TSESTree.MemberExpression).property;
    if (prop.type === 'Identifier' && SPAWN_FUNCTIONS.has((prop as TSESTree.Identifier).name)) {
      return (prop as TSESTree.Identifier).name;
    }
  }
  return null;
}

export function detectCommandInjection(result: ParseResult): Finding[] {
  const findings: Finding[] = [];
  const reported = new Set<number>();

  walkNode(result.ast, (node) => {
    if (node.type !== 'CallExpression') return;
    const call = node as TSESTree.CallExpression;

    const fnName = isSpawnCall(call.callee as TSESTree.LeftHandSideExpression);
    if (!fnName) return;
    if (call.arguments.length === 0) return;

    const firstArg = call.arguments[0];
    if (firstArg.type === 'SpreadElement') return;

    // Only flag when the command itself (first arg) is dynamic
    if (!isStaticCommand(firstArg as TSESTree.Node)) {
      const line = node.loc!.start.line;
      if (!reported.has(line)) {
        reported.add(line);
        findings.push({
          type: 'COMMAND_INJECTION',
          severity: 'high',
          line,
          column: node.loc!.start.column,
          snippet: getSnippet(result, line),
          message:
            `${fnName}() called with a dynamic command. If the command name originates from ` +
            `user input, an attacker can execute arbitrary programs. Use a hardcoded command ` +
            `string and pass only sanitized arguments in the args array.`,
        });
      }
    }
  });

  return findings;
}
