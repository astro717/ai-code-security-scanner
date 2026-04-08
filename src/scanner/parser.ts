import * as fs from 'fs';
import { parse } from '@typescript-eslint/parser';
import type { TSESTree } from '@typescript-eslint/types';

export interface ParseResult {
  ast: TSESTree.Program;
  code: string;
  lines: string[];
  /** Source file path, if the result was produced from a file on disk. */
  filePath?: string;
}

const BASE_PARSE_OPTIONS = {
  jsx: true,
  loc: true,
  range: true,
  tokens: true,
  comment: true,
  errorOnUnknownASTType: false,
};

export function parseFile(filePath: string): ParseResult {
  const code = fs.readFileSync(filePath, 'utf-8');
  return parseCode(code, filePath);
}

export function parseCode(code: string, filename = 'input.tsx'): ParseResult {
  const ast = parse(code, { ...BASE_PARSE_OPTIONS, filePath: filename }) as unknown as TSESTree.Program;
  return {
    ast,
    code,
    lines: code.split('\n'),
    filePath: filename,
  };
}
