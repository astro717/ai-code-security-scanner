"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.getSnippet = getSnippet;
exports.walkNode = walkNode;
exports.getLiteralValue = getLiteralValue;
/**
 * Extracts the trimmed source line at the given 1-based line number from a
 * ParseResult. Returns an empty string when the line is out of range (e.g.
 * for synthetic or generated code). Use this in every detector instead of the
 * inline pattern `result.lines[line - 1]?.trim() ?? ''` so snippet extraction
 * is consistent and easy to update in one place.
 *
 * @param result - The ParseResult whose `lines` array holds the source lines.
 * @param line   - 1-based line number (matching AST node.loc.start.line).
 */
function getSnippet(result, line) {
    return result.lines[line - 1]?.trim() ?? '';
}
/**
 * Recursively walks an AST node, invoking callback for every node in the tree.
 * Extracted from individual detectors to provide a single canonical implementation.
 */
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
 * Extracts the primitive value from a Literal AST node.
 * Returns undefined for any non-literal node type.
 */
function getLiteralValue(node) {
    if (node.type === 'Literal') {
        return node.value;
    }
    return undefined;
}
//# sourceMappingURL=utils.js.map