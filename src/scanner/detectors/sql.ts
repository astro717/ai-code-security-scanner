import { TSESTree } from '@typescript-eslint/types';
import { ParseResult } from '../parser';
import { Finding } from '../reporter';

const SQL_FUNCTION_NAMES = /^(query|execute|raw|db|sql|run|all|get|prepare)$/i;
const SQL_MEMBER_NAMES = /\.(query|execute|raw|run|all|get|prepare)\s*\(/; // kept for reference
// ORM raw-query methods: prisma.$queryRaw, prisma.$executeRaw, repository.query
const ORM_RAW_METHODS = /^\$(queryRaw|executeRaw|queryRawUnsafe|executeRawUnsafe)$/;

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

function isDynamic(node: TSESTree.Node): boolean {
  if (isStringLiteral(node)) return false;
  if (node.type === 'TemplateLiteral') {
    return (node as TSESTree.TemplateLiteral).expressions.length > 0;
  }
  if (node.type === 'BinaryExpression') {
    const bin = node as TSESTree.BinaryExpression;
    if (bin.operator === '+') {
      return isDynamic(bin.left) || isDynamic(bin.right) ||
        (!isStringLiteral(bin.left) || !isStringLiteral(bin.right));
    }
  }
  return true;
}

function isSQLCallExpression(node: TSESTree.CallExpression): boolean {
  const callee = node.callee;
  if (callee.type === 'Identifier') {
    return SQL_FUNCTION_NAMES.test(callee.name);
  }
  if (callee.type === 'MemberExpression') {
    const prop = callee.property;
    if (prop.type === 'Identifier') {
      return SQL_FUNCTION_NAMES.test(prop.name) || ORM_RAW_METHODS.test(prop.name);
    }
  }
  return false;
}

function isORMTaggedTemplate(node: TSESTree.TaggedTemplateExpression): boolean {
  const tag = node.tag;
  if (tag.type !== 'MemberExpression') return false;
  const prop = (tag as TSESTree.MemberExpression).property;
  if (prop.type !== 'Identifier') return false;
  return ORM_RAW_METHODS.test((prop as TSESTree.Identifier).name);
}

export function detectSQLInjection(result: ParseResult): Finding[] {
  const findings: Finding[] = [];
  const reported = new Set<number>();

  walkNode(result.ast, (node) => {
    // Case 1: CallExpression — db.query(dynamic), repository.query(dynamic), prisma.$queryRaw(dynamic)
    if (node.type === 'CallExpression') {
      const call = node as TSESTree.CallExpression;

      if (!isSQLCallExpression(call)) return;
      if (call.arguments.length === 0) return;

      const firstArg = call.arguments[0];
      if (firstArg.type === 'SpreadElement') return;

      if (isDynamic(firstArg as TSESTree.Node)) {
        const line = node.loc!.start.line;
        if (!reported.has(line)) {
          reported.add(line);
          findings.push({
            type: 'SQL_INJECTION',
            severity: 'critical',
            line,
            column: node.loc!.start.column,
            snippet: result.lines[line - 1]?.trim() ?? '',
            message: 'Dynamic value passed directly to SQL query function. Use parameterized queries.',
          });
        }
      }
      return;
    }

    // Case 2: TaggedTemplateExpression — prisma.$queryRaw`SELECT ... ${expr}`
    if (node.type === 'TaggedTemplateExpression') {
      const tagged = node as TSESTree.TaggedTemplateExpression;
      if (!isORMTaggedTemplate(tagged)) return;

      // Only flag if the template has dynamic expressions
      if (tagged.quasi.expressions.length > 0) {
        const line = node.loc!.start.line;
        if (!reported.has(line)) {
          reported.add(line);
          findings.push({
            type: 'SQL_INJECTION',
            severity: 'critical',
            line,
            column: node.loc!.start.column,
            snippet: result.lines[line - 1]?.trim() ?? '',
            message:
              'ORM raw query (prisma.$queryRaw / $executeRaw) called with a dynamic template literal. ' +
              'Use Prisma.sql tagged template or parameterized inputs to prevent SQL injection.',
          });
        }
      }
    }
  });

  return findings;
}
