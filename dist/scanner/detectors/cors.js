"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.detectCORSMisconfiguration = detectCORSMisconfiguration;
const utils_1 = require("../utils");
/**
 * Extracts properties from an ObjectExpression as a map from key to value node.
 */
function objectProps(node) {
    const props = new Map();
    if (node.type !== 'ObjectExpression')
        return props;
    for (const prop of node.properties) {
        if (prop.type !== 'Property')
            continue;
        const key = prop.key.type === 'Identifier'
            ? prop.key.name
            : prop.key.type === 'Literal'
                ? String(prop.key.value)
                : null;
        if (key !== null)
            props.set(key, prop.value);
    }
    return props;
}
// ── Pattern 1: cors({ origin: '*', credentials: true }) ──────────────────────
/**
 * Detects calls to cors({ origin: '*', credentials: true }).
 * Allowing wildcard origin with credentials exposes all cookies/auth headers
 * to any origin, enabling cross-site credential theft.
 */
function detectWildcardWithCredentials(result) {
    const findings = [];
    const reported = new Set();
    (0, utils_1.walkNode)(result.ast, (node) => {
        if (node.type !== 'CallExpression')
            return;
        const call = node;
        // Match: cors(...)
        if (call.callee.type !== 'Identifier' ||
            call.callee.name !== 'cors')
            return;
        if (call.arguments.length === 0 || call.arguments[0]?.type !== 'ObjectExpression')
            return;
        const opts = objectProps(call.arguments[0]);
        const originNode = opts.get('origin');
        const credentialsNode = opts.get('credentials');
        if (!originNode || !credentialsNode)
            return;
        const originVal = (0, utils_1.getLiteralValue)(originNode);
        const credentialsVal = (0, utils_1.getLiteralValue)(credentialsNode);
        if (originVal === '*' && credentialsVal === true) {
            const line = node.loc.start.line;
            if (!reported.has(line)) {
                reported.add(line);
                findings.push({
                    type: 'CORS_MISCONFIGURATION',
                    severity: 'high',
                    line,
                    column: node.loc.start.column,
                    snippet: result.lines[line - 1]?.trim() ?? '',
                    message: 'cors() is configured with origin: \'*\' and credentials: true. ' +
                        'Browsers block this combination per the CORS spec, but some older libraries or non-browser clients may still send credentials. ' +
                        'Use an explicit allowlist of trusted origins instead of wildcard when credentials are required.',
                    confidence: 0.78,
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
function detectReflectedOriginHeader(result) {
    const findings = [];
    const reported = new Set();
    (0, utils_1.walkNode)(result.ast, (node) => {
        if (node.type !== 'CallExpression')
            return;
        const call = node;
        // Match: res.setHeader(...) or res.header(...)
        if (call.callee.type !== 'MemberExpression')
            return;
        const mem = call.callee;
        if (mem.property.type !== 'Identifier')
            return;
        const method = mem.property.name;
        if (!['setHeader', 'header', 'set'].includes(method))
            return;
        if (call.arguments.length < 2)
            return;
        const headerNameNode = call.arguments[0];
        if (!headerNameNode || headerNameNode.type === 'SpreadElement')
            return;
        const headerName = (0, utils_1.getLiteralValue)(headerNameNode);
        if (typeof headerName !== 'string')
            return;
        if (headerName.toLowerCase() !== 'access-control-allow-origin')
            return;
        // Check if the value is derived from req.headers.origin / req.headers['origin']
        const valueNode = call.arguments[1];
        if (!valueNode || valueNode.type === 'SpreadElement')
            return;
        function isOriginHeader(n) {
            if (n.type !== 'MemberExpression')
                return false;
            const m = n;
            // req.headers.origin  OR  req.headers['origin']
            if (m.object.type !== 'MemberExpression')
                return false;
            const parent = m.object;
            if (parent.object.type === 'Identifier' &&
                parent.object.name === 'req' &&
                parent.property.type === 'Identifier' &&
                parent.property.name === 'headers') {
                const key = m.computed
                    ? (0, utils_1.getLiteralValue)(m.property)
                    : m.property.type === 'Identifier'
                        ? m.property.name
                        : null;
                return key === 'origin';
            }
            return false;
        }
        if (isOriginHeader(valueNode)) {
            const line = node.loc.start.line;
            if (!reported.has(line)) {
                reported.add(line);
                findings.push({
                    type: 'CORS_MISCONFIGURATION',
                    severity: 'high',
                    line,
                    column: node.loc.start.column,
                    snippet: result.lines[line - 1]?.trim() ?? '',
                    message: 'Access-Control-Allow-Origin is set to the reflected value of req.headers.origin. ' +
                        'This unconditionally trusts any origin and bypasses CORS restrictions. ' +
                        'Validate the origin against an explicit allowlist before reflecting it.',
                    confidence: 0.78,
                });
            }
        }
    });
    return findings;
}
// ── Exported detector ─────────────────────────────────────────────────────────
function detectCORSMisconfiguration(result) {
    return [
        ...detectWildcardWithCredentials(result),
        ...detectReflectedOriginHeader(result),
    ];
}
//# sourceMappingURL=cors.js.map