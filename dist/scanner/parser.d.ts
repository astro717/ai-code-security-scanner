import type { TSESTree } from '@typescript-eslint/types';
export interface ParseResult {
    ast: TSESTree.Program;
    code: string;
    lines: string[];
}
export declare function parseFile(filePath: string): ParseResult;
export declare function parseCode(code: string, filename?: string): ParseResult;
//# sourceMappingURL=parser.d.ts.map