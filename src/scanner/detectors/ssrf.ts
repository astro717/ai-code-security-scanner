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

/**
 * Returns true if the node is a static string literal or a template literal
 * with no dynamic expressions — i.e. the URL is fully hardcoded and safe.
 */
function isStaticUrl(node: TSESTree.Node): boolean {
  if (node.type === 'Literal') return true;
  if (node.type === 'TemplateLiteral') {
    return (node as TSESTree.TemplateLiteral).expressions.length === 0;
  }
  return false;
}

/**
 * HTTP client function patterns that accept a URL as their first argument:
 *   - fetch(url, ...)
 *   - http.get(url, ...) / https.get(url, ...)
 *   - http.request(url, ...) / https.request(url, ...)
 *   - axios(url) / axios.get/post/put/patch/delete/head/request(url, ...)
 */
const STANDALONE_HTTP_FNS = new Set(['fetch']);
const MEMBER_HTTP_OBJECTS = new Set(['http', 'https']);
const MEMBER_HTTP_METHODS = new Set(['get', 'request', 'post', 'put', 'patch', 'delete', 'head']);
const AXIOS_METHODS = new Set(['get', 'post', 'put', 'patch', 'delete', 'head', 'request']);

function isSsrfCall(call: TSESTree.CallExpression): boolean {
  const callee = call.callee;

  // fetch(url)
  if (callee.type === 'Identifier' && STANDALONE_HTTP_FNS.has((callee as TSESTree.Identifier).name)) {
    return true;
  }

  if (callee.type === 'MemberExpression' && !callee.computed) {
    const obj = (callee as TSESTree.MemberExpression).object;
    const prop = (callee as TSESTree.MemberExpression).property;
    if (prop.type !== 'Identifier') return false;
    const propName = (prop as TSESTree.Identifier).name;

    // http.get / https.get / http.request / https.request
    if (obj.type === 'Identifier') {
      const objName = (obj as TSESTree.Identifier).name;
      if (MEMBER_HTTP_OBJECTS.has(objName) && MEMBER_HTTP_METHODS.has(propName)) {
        return true;
      }
      // axios.get / axios.post / ... / axios itself (axios(url))
      if (objName === 'axios' && AXIOS_METHODS.has(propName)) {
        return true;
      }
    }
  }

  // bare axios(url) call — callee is Identifier 'axios'
  if (callee.type === 'Identifier' && (callee as TSESTree.Identifier).name === 'axios') {
    return true;
  }

  return false;
}

/**
 * Detects SSRF (Server-Side Request Forgery): calls to fetch(), axios.get/post(),
 * http.get(), https.get(), etc. where the URL argument is dynamic (a variable
 * or a template literal with expressions) rather than a static string.
 */
export function detectSSRF(result: ParseResult): Finding[] {
  const findings: Finding[] = [];
  const reported = new Set<number>();

  walkNode(result.ast, (node) => {
    if (node.type !== 'CallExpression') return;

    const call = node as TSESTree.CallExpression;
    if (!isSsrfCall(call)) return;

    const args = call.arguments;
    if (args.length === 0) return;

    const firstArg = args[0];
    if (firstArg.type === 'SpreadElement') return;

    // Only flag if the URL is dynamic (non-static)
    if (!isStaticUrl(firstArg as TSESTree.Node)) {
      const line = node.loc!.start.line;
      if (!reported.has(line)) {
        reported.add(line);

        // Build a human-readable function name for the message
        let fnLabel = 'HTTP call';
        const callee = call.callee;
        if (callee.type === 'Identifier') {
          fnLabel = (callee as TSESTree.Identifier).name + '()';
        } else if (callee.type === 'MemberExpression' && !callee.computed) {
          const obj = (callee as TSESTree.MemberExpression).object;
          const prop = (callee as TSESTree.MemberExpression).property;
          const objStr = obj.type === 'Identifier' ? (obj as TSESTree.Identifier).name : '...';
          const propStr = prop.type === 'Identifier' ? (prop as TSESTree.Identifier).name : '...';
          fnLabel = `${objStr}.${propStr}()`;
        }

        findings.push({
          type: 'SSRF',
          severity: 'high',
          line,
          column: node.loc!.start.column,
          snippet: result.lines[line - 1]?.trim() ?? '',
          message:
            `${fnLabel} called with a dynamic URL. If the URL originates from user input, ` +
            `an attacker can force the server to make requests to internal services (SSRF). ` +
            `Validate and whitelist allowed URL origins before making outbound requests.`,
        });
      }
    }
  });

  return findings;
}
