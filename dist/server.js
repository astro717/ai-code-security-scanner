"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const cors_1 = __importDefault(require("cors"));
const parser_1 = require("./scanner/parser");
const secrets_1 = require("./scanner/detectors/secrets");
const sql_1 = require("./scanner/detectors/sql");
const shell_1 = require("./scanner/detectors/shell");
const eval_1 = require("./scanner/detectors/eval");
const reporter_1 = require("./scanner/reporter");
const app = (0, express_1.default)();
const PORT = process.env.PORT ?? 3001;
app.use((0, cors_1.default)());
app.use(express_1.default.json({ limit: '1mb' }));
app.get('/health', (_req, res) => {
    res.json({ status: 'ok', version: '0.1.0' });
});
app.post('/scan', (req, res) => {
    const { code, filename } = req.body;
    if (!code || typeof code !== 'string') {
        res.status(400).json({ error: 'Missing required field: code (string)' });
        return;
    }
    let parsed;
    try {
        parsed = (0, parser_1.parseCode)(code, filename ?? 'input.tsx');
    }
    catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        res.status(400).json({ error: `Parse error: ${msg}` });
        return;
    }
    const findings = [
        ...(0, secrets_1.detectSecrets)(parsed),
        ...(0, sql_1.detectSQLInjection)(parsed),
        ...(0, shell_1.detectShellInjection)(parsed),
        ...(0, eval_1.detectEval)(parsed),
    ].map((f) => ({ ...f, file: filename ?? 'input' }));
    console.log(`[scan] ${filename ?? 'input'} → ${findings.length} findings`);
    res.json({ findings, summary: (0, reporter_1.summarize)(findings) });
});
app.listen(PORT, () => {
    console.log(`AI Security Scanner server running on http://localhost:${PORT}`);
});
//# sourceMappingURL=server.js.map