"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.parseFile = parseFile;
exports.parseCode = parseCode;
const fs = __importStar(require("fs"));
const parser_1 = require("@typescript-eslint/parser");
const BASE_PARSE_OPTIONS = {
    jsx: true,
    loc: true,
    range: true,
    tokens: true,
    comment: true,
    errorOnUnknownASTType: false,
};
function parseFile(filePath) {
    const code = fs.readFileSync(filePath, 'utf-8');
    return parseCode(code, filePath);
}
function parseCode(code, filename = 'input.tsx') {
    const ast = (0, parser_1.parse)(code, { ...BASE_PARSE_OPTIONS, filePath: filename });
    return {
        ast,
        code,
        lines: code.split('\n'),
    };
}
//# sourceMappingURL=parser.js.map