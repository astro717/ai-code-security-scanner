import { TSESTree } from '@typescript-eslint/types';
import { ParseResult } from '../parser';
import { Finding } from '../reporter';
import { walkNode, getLiteralValue } from '../utils';

/**
 * Extracts properties from an ObjectExpression as a map from key to value node.
 */
function objectProps(node: TSESTree.Node): Map<string, TSESTree.Node> {
  const props = new Map<string, TSESTree.Node>();
  if (node.type !== 'ObjectExpression') return props;
  for (const prop of (node as TSESTree.ObjectExpression).properties) {
    if (prop.type !== 'Property') continue;
    const key = prop.key.type === 'Identifier'
      ? (prop.key as TSESTree.Identifier).name
      : prop.key.type === 'Literal'
        ? String((prop.key as TSESTree.Literal).value)
        : null;
    if (key !== null) props.set(key, prop.value);
  }
  return props;
}

// ── Pattern 1: cors({ origin: '*', credentials: true }) ──────────────────────

/**
 * Detects calls to cors({ origin: '*', credentials: true }).
 * Allowing wildcard origin with credentials exposes all cookies/auth headers
 * to any origin, enabling cross-site credential theft.
 */
function detectWildcardWithCredentials(result: ParseResult): Finding[] {
  const findings: Finding[] = [];
  const reported = new Set<number>();

  walkNode(result.ast, (node) => {
    if (node.type !== 'CallExpression') return;
    const call = node as TSESTree.CallExpression;

    // Match: cors(...)
    if (
      call.callee.type !== 'Identifier' ||
      (call.callee as TSESTree.Identifier).name !== 'cors'
    ) return;

    if (call.arguments.length === 0 || call.arguments[0]?.type !== 'ObjectExpression') return;

    const opts = objectProps(call.arguments[0] as TSESTree.Node);
    const originNode = opts.get('origin');
    const credentialsNode = opts.get('credentials');

    if (!originNode || !credentialsNode) return;

    const originVal = getLiteralValue(originNode);
    const credentialsVal = getLiteralValue(credentialsNode);

    if (originVal === '*' && credentialsVal === true) {
      const line = node.loc!.start.line;
      if (!reported.has(line)) {
        reported.add(line);
        findings.push({
          type: 'CORS_MISCONFIGURATION',
          severity: 'high',
          line,
          column: node.loc!.start.column,
          snippet: result.lines[line - 1]?.trim() ?? '',
          message:
            'cors() is configured with origin: \'*\' and credentials: true. ' +
            'Browsers block this combination per the CORS spec, but some older libraries or non-browser clients may still send credentials. ' +
            'Use an explicit allowlist of trusted origins instead of wildcard when credentials are required.',
        });
      }
    }
  });

  return findings;
}

// ── Pattern 2: Access-Control-Allow-Origin reflected from request header ──────

/**
 * Detects setting the Access-Control-Allow-Origin header to a value derived
 * from the incoming request (e.g. req.headers.origin, req.headers['origin']).
 *
 * Reflecting the Origin header unconditionally means any origin is trusted,
 * equivalent to '*' but bypassing the credentials restriction.
 */
function detectReflectedOriginHeader(result: ParseResult): Finding[] {
  const findings: Finding[] = [];
  const reported = new Set<number>();

  walkNode(result.ast, (node) => {
    if (node.type !== 'CallExpression') return;
    const call = node as TSESTree.CallExpression;

    // Match: res.setHeader(...) or res.header(...)
    if (call.callee.type !== 'MemberExpression') return;
    const mem = call.callee as TSESTree.MemberExpression;
    if (mem.property.type !== 'Identifier') return;
    const method = (mem.property as TSESTree.Identifier).name;
    if (!['setHeader', 'header', 'set'].includes(method)) return;

    if (call.arguments.length < 2) return;
    const headerNameNode = call.arguments[0];
    if (!headerNameNode || headerNameNode.type === 'SpreadElement') return;
    const headerName = getLiteralValue(headerNameNode as TSESTree.Node);
    if (typeof headerName !== 'string') return;
    if (headerName.toLowerCase() !== 'access-control-allow-origin') return;

    // Check if the value is derived from req.headers.origin / req.headers['origin']
    const valueNode = call.arguments[1];
    if (!valueNode || valueNode.type === 'SpreadElement') return;

    function isOriginHeader(n: TSESTree.Node): boolean {
      if (n.type !== 'MemberExpression') return false;
      const m = n as TSESTree.MemberExpression;
      // req.headers.origin  OR  req.headers['origin']
      if (m.object.type !== 'MemberExpression') return false;
      const parent = m.object as TSESTree.MemberExpression;
      if (
        parent.object.type === 'Identifier' &&
        (parent.object as TSESTree.Identifier).name === 'req' &&
        parent.property.type === 'Identifier' &&
        (parent.property as TSESTree.Identifier).name === 'headers'
      ) {
        const key = m.computed
          ? getLiteralValue(m.property)
          : m.property.type === 'Identifier'
            ? (m.property as TSESTree.Identifier).name
            : null;
        return key === 'origin';
      }
      return false;
    }

    if (isOriginHeader(valueNode as TSESTree.Node)) {
      const line = node.loc!.start.line;
      if (!reported.has(line)) {
        reported.add(line);
        findings.push({
          type: 'CORS_MISCONFIGURATION',
          severity: 'high',
          line,
          column: node.loc!.start.column,
          snippet: result.lines[line - 1]?.trim() ?? '',
          message:
            'Access-Control-Allow-Origin is set to the reflected value of req.headers.origin. ' +
            'This unconditionally trusts any origin and bypasses CORS restrictions. ' +
            'Validate the origin against an explicit allowlist before reflecting it.',
        });
      }
    }
  });

  return findings;
}

// ── Exported detector ─────────────────────────────────────────────────────────

export function detectCORSMisconfiguration(result: ParseResult): Finding[] {
  return [
    ...detectWildcardWithCredentials(result),
    ...detectReflectedOriginHeader(result),
  ];
}
