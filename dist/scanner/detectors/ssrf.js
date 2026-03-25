"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.detectSSRF = detectSSRF;
function walkNode(node, callback) {
    callback(node);
    for (const key of Object.keys(node)) {
        const child = node[key];
        if (child && typeof child === 'object') {
            if (Array.isArray(child)) {
                child.forEach((c) => {
                    if (c && typeof c === 'object' && 'type' in c)
                        walkNode(c, callback);
                });
            }
            else if ('type' in child) {
                walkNode(child, callback);
            }
        }
    }
}
/**
 * Returns true if the node is a static string literal or a template literal
 * with no dynamic expressions — i.e. the URL is fully hardcoded and safe.
 */
function isStaticUrl(node) {
    if (node.type === 'Literal')
        return true;
    if (node.type === 'TemplateLiteral') {
        return node.expressions.length === 0;
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
function isSsrfCall(call) {
    const callee = call.callee;
    // fetch(url)
    if (callee.type === 'Identifier' && STANDALONE_HTTP_FNS.has(callee.name)) {
        return true;
    }
    if (callee.type === 'MemberExpression' && !callee.computed) {
        const obj = callee.object;
        const prop = callee.property;
        if (prop.type !== 'Identifier')
            return false;
        const propName = prop.name;
        // http.get / https.get / http.request / https.request
        if (obj.type === 'Identifier') {
            const objName = obj.name;
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
    if (callee.type === 'Identifier' && callee.name === 'axios') {
        return true;
    }
    return false;
}
// ── Taint sources ─────────────────────────────────────────────────────────────
/**
 * Returns true if the node represents a tainted source — i.e. a value that
 * originates from user-controlled request input:
 *   req.query.xxx  / req.query['xxx']
 *   req.body.xxx   / req.body['xxx']
 *   req.params.xxx / req.params['xxx']
 *   req.headers.xxx
 */
function isTaintSource(node) {
    if (node.type !== 'MemberExpression')
        return false;
    const mem = node;
    // req.query / req.body / req.params / req.headers  (depth 1 — e.g. req.body itself)
    if (mem.object.type === 'Identifier' &&
        mem.object.name === 'req' &&
        mem.property.type === 'Identifier') {
        const propName = mem.property.name;
        if (['query', 'body', 'params', 'headers'].includes(propName)) {
            return true;
        }
    }
    // req.query.xxx / req.body.xxx / req.params.xxx / req.headers.xxx  (depth 2)
    if (mem.object.type === 'MemberExpression') {
        const parent = mem.object;
        if (parent.object.type === 'Identifier' &&
            parent.object.name === 'req' &&
            parent.property.type === 'Identifier') {
            const parentProp = parent.property.name;
            if (['query', 'body', 'params', 'headers'].includes(parentProp)) {
                return true;
            }
        }
    }
    return false;
}
/**
 * Builds a taint map: variable name -> true if that variable was assigned from
 * a taint source (req.query/req.body/req.params/req.headers) anywhere in the AST.
 *
 * Handles:
 *   const url = req.query.url;
 *   let target = req.body.target;
 *   url = req.query.url;             (reassignment)
 *   const { url } = req.query;       (destructuring)
 */
function buildTaintMap(ast) {
    const tainted = new Set();
    walkNode(ast, (node) => {
        // const/let/var x = <taint>
        if (node.type === 'VariableDeclarator') {
            const decl = node;
            if (!decl.init)
                return;
            // Simple: const url = req.query.url
            if (decl.id.type === 'Identifier' && isTaintSource(decl.init)) {
                tainted.add(decl.id.name);
            }
            // Destructuring: const { url } = req.query
            if (decl.id.type === 'ObjectPattern' && isTaintSource(decl.init)) {
                const pat = decl.id;
                for (const prop of pat.properties) {
                    if (prop.type === 'Property' && prop.value.type === 'Identifier') {
                        tainted.add(prop.value.name);
                    }
                    else if (prop.type === 'RestElement' && prop.argument.type === 'Identifier') {
                        tainted.add(prop.argument.name);
                    }
                }
            }
        }
        // x = <taint>  (assignment expression)
        if (node.type === 'AssignmentExpression') {
            const assign = node;
            if (assign.left.type === 'Identifier' && isTaintSource(assign.right)) {
                tainted.add(assign.left.name);
            }
        }
    });
    return tainted;
}
/**
 * Returns true if a node is tainted — either it's a direct taint source or
 * it's an Identifier whose name is in the taint map.
 */
function isTainted(node, taintMap) {
    if (isTaintSource(node))
        return true;
    if (node.type === 'Identifier') {
        return taintMap.has(node.name);
    }
    // Template literal: `${taintedVar}/path` — tainted if any expression is tainted
    if (node.type === 'TemplateLiteral') {
        return node.expressions.some((e) => isTainted(e, taintMap));
    }
    return false;
}
// ── Main detector ─────────────────────────────────────────────────────────────
/**
 * Detects SSRF (Server-Side Request Forgery): calls to fetch(), axios.get/post(),
 * http.get(), https.get(), etc. where the URL argument is dynamic (a variable
 * or a template literal with expressions) rather than a static string.
 *
 * Additionally performs single-scope taint tracking: if the URL variable was
 * assigned from req.query / req.body / req.params / req.headers (including
 * multi-hop assignments), a higher-confidence SSRF finding is emitted.
 */
function detectSSRF(result) {
    const findings = [];
    const reported = new Set();
    // Build taint map once for the entire file
    const taintMap = buildTaintMap(result.ast);
    walkNode(result.ast, (node) => {
        if (node.type !== 'CallExpression')
            return;
        const call = node;
        if (!isSsrfCall(call))
            return;
        const args = call.arguments;
        if (args.length === 0)
            return;
        const firstArg = args[0];
        if (firstArg.type === 'SpreadElement')
            return;
        const argNode = firstArg;
        // Only flag if the URL is dynamic (non-static)
        if (!isStaticUrl(argNode)) {
            const line = node.loc.start.line;
            if (!reported.has(line)) {
                reported.add(line);
                // Build a human-readable function name for the message
                let fnLabel = 'HTTP call';
                const callee = call.callee;
                if (callee.type === 'Identifier') {
                    fnLabel = callee.name + '()';
                }
                else if (callee.type === 'MemberExpression' && !callee.computed) {
                    const obj = callee.object;
                    const prop = callee.property;
                    const objStr = obj.type === 'Identifier' ? obj.name : '...';
                    const propStr = prop.type === 'Identifier' ? prop.name : '...';
                    fnLabel = `${objStr}.${propStr}()`;
                }
                // Check whether the URL can be traced back to user-controlled input
                const userControlled = isTainted(argNode, taintMap);
                findings.push({
                    type: 'SSRF',
                    severity: 'high',
                    line,
                    column: node.loc.start.column,
                    snippet: result.lines[line - 1]?.trim() ?? '',
                    message: userControlled
                        ? `${fnLabel} called with a URL derived from user-controlled request input (req.query/req.body). ` +
                            `An attacker can force the server to make requests to internal services (SSRF). ` +
                            `Validate and whitelist allowed URL origins before making outbound requests.`
                        : `${fnLabel} called with a dynamic URL. If the URL originates from user input, ` +
                            `an attacker can force the server to make requests to internal services (SSRF). ` +
                            `Validate and whitelist allowed URL origins before making outbound requests.`,
                });
            }
        }
    });
    return findings;
}
//# sourceMappingURL=ssrf.js.map