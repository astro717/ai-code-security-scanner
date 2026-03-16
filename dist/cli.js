#!/usr/bin/env node
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
const commander_1 = require("commander");
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
const parser_1 = require("./scanner/parser");
const secrets_1 = require("./scanner/detectors/secrets");
const sql_1 = require("./scanner/detectors/sql");
const shell_1 = require("./scanner/detectors/shell");
const eval_1 = require("./scanner/detectors/eval");
const reporter_1 = require("./scanner/reporter");
const SUPPORTED_EXTENSIONS = new Set(['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs']);
function collectFiles(targetPath) {
    const stat = fs.statSync(targetPath);
    if (stat.isFile())
        return [targetPath];
    const files = [];
    function walk(dir) {
        for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
            const full = path.join(dir, entry.name);
            if (entry.isDirectory() && !entry.name.startsWith('.') && entry.name !== 'node_modules') {
                walk(full);
            }
            else if (entry.isFile() && SUPPORTED_EXTENSIONS.has(path.extname(entry.name))) {
                files.push(full);
            }
        }
    }
    walk(targetPath);
    return files;
}
function scanFile(filePath) {
    try {
        const parsed = (0, parser_1.parseFile)(filePath);
        return [
            ...(0, secrets_1.detectSecrets)(parsed),
            ...(0, sql_1.detectSQLInjection)(parsed),
            ...(0, shell_1.detectShellInjection)(parsed),
            ...(0, eval_1.detectEval)(parsed),
        ].map((f) => ({ ...f, file: filePath }));
    }
    catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        console.error(`  [skip] ${filePath}: ${msg}`);
        return [];
    }
}
commander_1.program
    .name('ai-sec-scan')
    .description('AST-based security scanner for AI-generated code')
    .version('0.1.0')
    .argument('[path]', 'File or directory to scan', '.')
    .option('--json', 'Output results as JSON')
    .option('--severity <level>', 'Minimum severity to report (critical|high|medium|low)', 'low')
    .action(async (targetPath, options) => {
    const resolved = path.resolve(targetPath);
    if (!fs.existsSync(resolved)) {
        console.error(`Error: path not found: ${resolved}`);
        process.exit(1);
    }
    const files = collectFiles(resolved);
    const allFindings = [];
    for (const file of files) {
        allFindings.push(...scanFile(file));
    }
    const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
    const minSeverity = severityOrder[options.severity] ?? 3;
    const filtered = allFindings.filter((f) => severityOrder[f.severity] <= minSeverity);
    if (options.json) {
        console.log((0, reporter_1.formatJSON)(filtered));
    }
    else {
        await (0, reporter_1.printFindings)(filtered, resolved);
    }
    const summary = (0, reporter_1.summarize)(filtered);
    if (summary.critical > 0 || summary.high > 0) {
        process.exit(1);
    }
});
commander_1.program.parse();
//# sourceMappingURL=cli.js.map