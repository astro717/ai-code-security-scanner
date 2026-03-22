import { TSESTree } from '@typescript-eslint/types';

/**
 * Recursively walks an AST node, invoking callback for every node in the tree.
 * Extracted from individual detectors to provide a single canonical implementation.
 */
export function walkNode(node: TSESTree.Node, callback: (n: TSESTree.Node) => void): void {
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
 * Extracts the primitive value from a Literal AST node.
 * Returns undefined for any non-literal node type.
 */
export function getLiteralValue(node: TSESTree.Node): string | boolean | null | undefined {
  if (node.type === 'Literal') {
    return (node as TSESTree.Literal).value as string | boolean | null;
  }
  return undefined;
}
