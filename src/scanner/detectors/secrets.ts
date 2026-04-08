import { TSESTree } from '@typescript-eslint/types';
import { ParseResult } from '../parser';
import { Finding } from '../reporter';

// Patterns that look like real secrets
const SECRET_VALUE_PATTERNS = [
  /^sk-[a-zA-Z0-9]{20,}/,           // OpenAI API keys
  /^ghp_[a-zA-Z0-9]{36}/,           // GitHub personal access tokens
  /^AKIA[0-9A-Z]{16}/,              // AWS access key IDs
  /^xoxb-[0-9]+-/,                  // Slack bot tokens
  /^xoxp-[0-9]+-/,                  // Slack user tokens
  /^AIza[0-9A-Za-z_-]{35}/,         // Google API keys
  /^[a-f0-9]{32,}$/,                // Generic hex secrets (32+ chars)
  /Bearer\s+[a-zA-Z0-9._-]{20,}/,  // Bearer tokens
  /^eyJ[a-zA-Z0-9._-]{20,}/,        // JWTs
];

// Variable names that suggest sensitive data
const SENSITIVE_VAR_NAMES = /(?:secret|password|passwd|token|apikey|api_key|private_key|auth_key|access_key|credentials?)\b/i;

function redact(value: string): string {
  if (value.length <= 8) return '****';
  return value.slice(0, 4) + '****' + value.slice(-4);
}

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

export function detectSecrets(result: ParseResult): Finding[] {
  const findings: Finding[] = [];

  walkNode(result.ast, (node) => {
    // Pattern 1: string literal value matches a known secret pattern
    if (node.type === 'Literal' && typeof node.value === 'string' && node.value.length > 8) {
      for (const pattern of SECRET_VALUE_PATTERNS) {
        if (pattern.test(node.value)) {
          findings.push({
            type: 'SECRET_HARDCODED',
            severity: 'critical',
            line: node.loc!.start.line,
            column: node.loc!.start.column,
            snippet: `"${redact(node.value)}"`,
            message: `Possible secret detected matching pattern ${pattern.source.slice(0, 20)}…`,
                confidence: 0.65,
          });
          break;
        }
      }
    }

    // Pattern 2: variable/property name suggests sensitive data + string literal value
    if (
      (node.type === 'VariableDeclarator' || node.type === 'AssignmentExpression' || node.type === 'Property') &&
      'init' in node || 'right' in node || 'value' in node
    ) {
      let name: string | null = null;
      let valueNode: TSESTree.Node | null | undefined = null;

      if (node.type === 'VariableDeclarator') {
        name = (node.id as TSESTree.Identifier)?.name ?? null;
        valueNode = node.init;
      } else if (node.type === 'AssignmentExpression') {
        name = (node.left as TSESTree.Identifier)?.name ?? null;
        valueNode = node.right;
      } else if (node.type === 'Property') {
        name = ((node.key as TSESTree.Identifier)?.name ?? (node.key as TSESTree.Literal)?.value?.toString()) ?? null;
        valueNode = node.value;
      }

      if (name && SENSITIVE_VAR_NAMES.test(name) && valueNode?.type === 'Literal' && typeof (valueNode as TSESTree.Literal).value === 'string') {
        const val = (valueNode as TSESTree.Literal).value as string;
        if (val.length > 0) {
          findings.push({
            type: 'SECRET_HARDCODED',
            severity: 'critical',
            line: node.loc!.start.line,
            column: node.loc!.start.column,
            snippet: `${name} = "${redact(val)}"`,
            message: `Sensitive variable "${name}" assigned a hardcoded string value.`,
                confidence: 0.65,
          });
        }
      }
    }
  });

  // Deduplicate by (line, type) to match the server-level dedup key (file, line, type).
  // Using (line, column) was overly granular and could let through duplicate findings
  // of different types on the same line, or miss duplicates at different columns.
  const seen = new Set<string>();
  return findings.filter((f) => {
    const key = `${f.line}:${f.type}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}
