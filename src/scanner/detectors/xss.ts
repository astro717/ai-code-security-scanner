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

function isLiteral(node: TSESTree.Node): boolean {
  return node.type === 'Literal';
}

function isDynamic(node: TSESTree.Node): boolean {
  if (isLiteral(node)) return false;
  if (node.type === 'TemplateLiteral') {
    return (node as TSESTree.TemplateLiteral).expressions.length > 0;
  }
  return true;
}

export function detectXSS(result: ParseResult): Finding[] {
  const findings: Finding[] = [];

  walkNode(result.ast, (node) => {
    // 1. dangerouslySetInnerHTML={{ __html: dynamicValue }}
    if (node.type === 'JSXAttribute') {
      const attr = node as TSESTree.JSXAttribute;
      const nameNode = attr.name;
      const attrName = nameNode.type === 'JSXIdentifier' ? nameNode.name : '';
      if (attrName === 'dangerouslySetInnerHTML' && attr.value) {
        // value is JSXExpressionContainer
        if (attr.value.type === 'JSXExpressionContainer') {
          const expr = (attr.value as TSESTree.JSXExpressionContainer).expression;
          if (expr.type !== 'JSXEmptyExpression') {
            // Check if __html property is dynamic
            let hasDynamicHtml = false;
            if (expr.type === 'ObjectExpression') {
              for (const prop of (expr as TSESTree.ObjectExpression).properties) {
                if (prop.type === 'Property') {
                  const p = prop as TSESTree.Property;
                  const keyName =
                    p.key.type === 'Identifier' ? (p.key as TSESTree.Identifier).name :
                    p.key.type === 'Literal' ? String((p.key as TSESTree.Literal).value) : '';
                  if (keyName === '__html' && isDynamic(p.value as TSESTree.Node)) {
                    hasDynamicHtml = true;
                  }
                }
              }
            } else {
              // dangerouslySetInnerHTML={variable} — treat as dynamic
              hasDynamicHtml = true;
            }

            if (hasDynamicHtml) {
              const line = node.loc!.start.line;
              findings.push({
                type: 'XSS',
                severity: 'critical',
                line,
                column: node.loc!.start.column,
                snippet: result.lines[line - 1]?.trim() ?? '',
                message: 'dangerouslySetInnerHTML with dynamic value. Unsanitized HTML leads to XSS.',
              });
            }
          }
        }
      }
    }

    // 2. element.innerHTML = variable  (AssignmentExpression)
    if (node.type === 'AssignmentExpression') {
      const assign = node as TSESTree.AssignmentExpression;
      if (
        assign.left.type === 'MemberExpression' &&
        !assign.left.computed
      ) {
        const prop = (assign.left as TSESTree.MemberExpression).property;
        const propName = prop.type === 'Identifier' ? (prop as TSESTree.Identifier).name : '';
        if (propName === 'innerHTML' || propName === 'outerHTML') {
          if (isDynamic(assign.right)) {
            const line = node.loc!.start.line;
            findings.push({
              type: 'XSS',
              severity: 'critical',
              line,
              column: node.loc!.start.column,
              snippet: result.lines[line - 1]?.trim() ?? '',
              message: `Assignment to .${propName} with dynamic value. Use textContent or sanitize the HTML first.`,
            });
          }
        }
      }
    }

    // 3. document.write(variable) / document.writeln(variable)
    if (node.type === 'CallExpression') {
      const call = node as TSESTree.CallExpression;
      if (
        call.callee.type === 'MemberExpression' &&
        !call.callee.computed
      ) {
        const obj = (call.callee as TSESTree.MemberExpression).object;
        const prop = (call.callee as TSESTree.MemberExpression).property;
        const objName = obj.type === 'Identifier' ? (obj as TSESTree.Identifier).name : '';
        const propName = prop.type === 'Identifier' ? (prop as TSESTree.Identifier).name : '';
        if (objName === 'document' && (propName === 'write' || propName === 'writeln')) {
          if (call.arguments.length > 0) {
            const firstArg = call.arguments[0];
            if (firstArg.type !== 'SpreadElement' && isDynamic(firstArg as TSESTree.Node)) {
              const line = node.loc!.start.line;
              findings.push({
                type: 'XSS',
                severity: 'critical',
                line,
                column: node.loc!.start.column,
                snippet: result.lines[line - 1]?.trim() ?? '',
                message: `document.${propName}() called with dynamic value. Avoid document.write() — it enables XSS.`,
              });
            }
          }
        }
      }
    }
  });

  return findings;
}
