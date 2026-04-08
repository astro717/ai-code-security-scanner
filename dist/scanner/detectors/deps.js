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
exports.KNOWN_VULNERABLE = void 0;
exports.checkCVEMapStaleness = checkCVEMapStaleness;
exports.parseVersion = parseVersion;
exports.isBelow = isBelow;
exports.detectUnsafeDepsFromJson = detectUnsafeDepsFromJson;
exports.detectUnsafeDeps = detectUnsafeDeps;
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
// ── Known vulnerable package versions ────────────────────────────────────────
// When a project dependency is pinned to a version below the safe threshold,
// a VULNERABLE_DEPENDENCY finding is emitted. Keep this list up to date as
// new CVEs are published.
//
// STALENESS CHECK: if the newest entry below is older than 90 days a runtime
// warning is emitted. Update the LAST_UPDATED constant whenever you add or
// revise entries.
/** ISO date of the most recent CVE entry added/updated in this file. */
const CVE_MAP_LAST_UPDATED = '2026-03-23';
const CVE_STALENESS_DAYS = 90;
function checkCVEMapStaleness() {
    const lastUpdated = new Date(CVE_MAP_LAST_UPDATED).getTime();
    const ageMs = Date.now() - lastUpdated;
    const ageDays = Math.floor(ageMs / (1000 * 60 * 60 * 24));
    if (ageDays > CVE_STALENESS_DAYS) {
        process.stderr.write(`[deps] Warning: CVE map was last updated ${ageDays} days ago (>${CVE_STALENESS_DAYS} day threshold). ` +
            `Consider refreshing KNOWN_VULNERABLE in src/scanner/detectors/deps.ts.\n`);
    }
}
exports.KNOWN_VULNERABLE = {
    // ── Prototype pollution ───────────────────────────────────────────────────
    'lodash': { below: '4.17.21', severity: 'critical', cve: 'CVE-2021-23337 / prototype pollution via template' },
    'lodash.merge': { below: '4.6.2', severity: 'critical', cve: 'CVE-2020-8203 / prototype pollution via merge' },
    'lodash.defaultsdeep': { below: '4.6.1', severity: 'critical', cve: 'CVE-2020-8203 / prototype pollution' },
    'minimist': { below: '1.2.6', severity: 'critical', cve: 'CVE-2021-44906 / prototype pollution' },
    'deep-extend': { below: '0.5.1', severity: 'critical', cve: 'CVE-2018-16492 / prototype pollution' },
    'merge': { below: '2.1.1', severity: 'high', cve: 'CVE-2018-16469 / prototype pollution' },
    'mixin-deep': { below: '1.3.2', severity: 'critical', cve: 'CVE-2019-10746 / prototype pollution' },
    'set-value': { below: '4.0.1', severity: 'critical', cve: 'CVE-2019-10747 / prototype pollution' },
    'node-forge': { below: '1.3.0', severity: 'high', cve: 'CVE-2022-24771 / RSA PKCS#1 signature bypass' },
    // ── HTTP / networking ─────────────────────────────────────────────────────
    'node-fetch': { below: '3.0.0', severity: 'high', cve: 'CVE-2022-0235 / exposure of sensitive info via redirect' },
    'axios': { below: '1.6.0', severity: 'high', cve: 'CVE-2023-45857 / CSRF via forged request' },
    'got': { below: '11.8.5', severity: 'high', cve: 'CVE-2022-33987 / open redirect' },
    'superagent': { below: '8.0.5', severity: 'medium', cve: 'CVE-2022-36623 / ReDoS in header parsing' },
    'request': { below: '2.88.2', severity: 'medium', cve: 'CVE-2023-28155 / SSRF via redirect' },
    // ── Authentication / JWT ──────────────────────────────────────────────────
    'jsonwebtoken': { below: '9.0.0', severity: 'high', cve: 'CVE-2022-23529 / arbitrary file write' },
    'passport': { below: '0.6.0', severity: 'high', cve: 'CVE-2022-25896 / session fixation' },
    'passport-jwt': { below: '4.0.1', severity: 'high', cve: 'CVE-2022-23543 / none algorithm bypass' },
    // ── Web frameworks ────────────────────────────────────────────────────────
    'express': { below: '4.19.0', severity: 'medium', cve: 'CVE-2024-29041 / open redirect via Host header' },
    'koa': { below: '2.14.0', severity: 'medium', cve: 'CVE-2023-25166 / request smuggling' },
    'fastify': { below: '4.10.0', severity: 'medium', cve: 'CVE-2022-31150 / ReDoS in content-type parsing' },
    // ── Templating / markdown ─────────────────────────────────────────────────
    'handlebars': { below: '4.7.7', severity: 'critical', cve: 'CVE-2021-23369 / prototype pollution via AST injection' },
    'marked': { below: '4.0.10', severity: 'medium', cve: 'CVE-2022-21681 / ReDoS' },
    'ejs': { below: '3.1.9', severity: 'critical', cve: 'CVE-2022-29078 / RCE via template injection' },
    'pug': { below: '3.0.1', severity: 'critical', cve: 'CVE-2021-21315 / code injection' },
    // ── Parsing / validation ──────────────────────────────────────────────────
    'semver': { below: '7.5.2', severity: 'high', cve: 'CVE-2022-25883 / ReDoS' },
    'xml2js': { below: '0.5.0', severity: 'high', cve: 'CVE-2023-0842 / prototype pollution' },
    'htmlparser2': { below: '8.0.0', severity: 'medium', cve: 'CVE-2021-33587 / ReDoS' },
    'ini': { below: '1.3.6', severity: 'critical', cve: 'CVE-2020-7788 / prototype pollution' },
    'js-yaml': { below: '4.0.0', severity: 'high', cve: 'CVE-2021-32748 / code execution via unsafe load' },
    // ── Utilities ─────────────────────────────────────────────────────────────
    'underscore': { below: '1.13.2', severity: 'critical', cve: 'CVE-2021-23358 / arbitrary code execution via template' },
    'async': { below: '3.2.2', severity: 'high', cve: 'CVE-2021-43138 / prototype pollution' },
    'tar': { below: '6.1.9', severity: 'high', cve: 'CVE-2021-37701 / path traversal in archive extraction' },
    'follow-redirects': { below: '1.15.4', severity: 'high', cve: 'CVE-2023-26159 / URL redirection to untrusted site' },
    'tough-cookie': { below: '4.1.3', severity: 'high', cve: 'CVE-2023-26136 / prototype pollution' },
    'ip': { below: '2.0.1', severity: 'high', cve: 'CVE-2024-29415 / SSRF via incorrect private IP detection' },
    'word-wrap': { below: '1.2.4', severity: 'medium', cve: 'CVE-2023-26115 / ReDoS' },
    'vm2': { below: '3.9.19', severity: 'critical', cve: 'CVE-2023-32314 / sandbox escape' },
    'shell-quote': { below: '1.8.1', severity: 'critical', cve: 'CVE-2021-42740 / command injection' },
    // ── Database ──────────────────────────────────────────────────────────────
    'mongoose': { below: '7.6.3', severity: 'high', cve: 'CVE-2023-3696 / prototype pollution via lean()' },
    'sequelize': { below: '6.35.0', severity: 'high', cve: 'CVE-2023-22578 / SQL injection via order clause' },
    // ── Build / dev tooling ───────────────────────────────────────────────────
    'webpack': { below: '5.76.0', severity: 'high', cve: 'CVE-2023-28154 / prototype pollution' },
    'terser': { below: '5.14.2', severity: 'high', cve: 'CVE-2022-25858 / code injection via crafted input' },
};
// ── Helpers ───────────────────────────────────────────────────────────────────
function parseVersion(v) {
    return v.replace(/^[\^~>=<v]/, '').split('.').map((n) => parseInt(n, 10) || 0);
}
function isBelow(current, threshold) {
    const c = parseVersion(current);
    const t = parseVersion(threshold);
    for (let i = 0; i < 3; i++) {
        if ((c[i] ?? 0) < (t[i] ?? 0))
            return true;
        if ((c[i] ?? 0) > (t[i] ?? 0))
            return false;
    }
    return false;
}
// ── Core analysis ─────────────────────────────────────────────────────────────
function analyseDepMap(allDeps, fileRef) {
    const findings = [];
    for (const [name, version] of Object.entries(allDeps)) {
        // Unpinned versions
        if (version === 'latest' || version === '*' || version === 'x') {
            findings.push({
                type: 'UNSAFE_DEPENDENCY',
                severity: 'medium',
                line: 1,
                column: 0,
                snippet: `"${name}": "${version}"`,
                message: `Dependency "${name}" pinned to "${version}" — unpinned versions can introduce breaking changes or malicious updates.`,
                file: fileRef,
                confidence: 0.80,
            });
        }
        // Known vulnerable versions
        const vuln = exports.KNOWN_VULNERABLE[name];
        if (vuln && isBelow(version, vuln.below)) {
            findings.push({
                type: 'VULNERABLE_DEPENDENCY',
                severity: vuln.severity,
                line: 1,
                column: 0,
                snippet: `"${name}": "${version}"`,
                message: `"${name}@${version}" is vulnerable (${vuln.cve}). Upgrade to >=${vuln.below}.`,
                file: fileRef,
                confidence: 0.80,
            });
        }
    }
    return findings;
}
// ── Public API ────────────────────────────────────────────────────────────────
/**
 * Scan a package.json provided as a raw JSON string (e.g. from the scan server
 * when the client uploads the file contents directly).
 */
function detectUnsafeDepsFromJson(packageJsonStr) {
    let pkg;
    try {
        pkg = JSON.parse(packageJsonStr);
    }
    catch {
        return [];
    }
    const allDeps = {
        ...(pkg.dependencies ?? {}),
        ...(pkg.devDependencies ?? {}),
    };
    return analyseDepMap(allDeps, 'package.json');
}
/**
 * Scan a project directory for an unsafe package.json. Also checks for a
 * missing lockfile. Used by the CLI when scanning a directory target.
 */
function detectUnsafeDeps(projectDir) {
    // Warn at runtime if the CVE map is getting stale
    checkCVEMapStaleness();
    const findings = [];
    const pkgPath = path.join(projectDir, 'package.json');
    if (!fs.existsSync(pkgPath))
        return findings;
    let pkg;
    try {
        pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf-8'));
    }
    catch {
        return findings;
    }
    const allDeps = {
        ...(pkg.dependencies ?? {}),
        ...(pkg.devDependencies ?? {}),
    };
    findings.push(...analyseDepMap(allDeps, pkgPath));
    // Check for missing lockfile
    const lockFiles = ['package-lock.json', 'yarn.lock', 'pnpm-lock.yaml'];
    const hasLockfile = lockFiles.some((lf) => fs.existsSync(path.join(projectDir, lf)));
    if (!hasLockfile && Object.keys(allDeps).length > 0) {
        findings.push({
            type: 'UNSAFE_DEPENDENCY',
            severity: 'medium',
            line: 1,
            column: 0,
            snippet: 'No lockfile found',
            message: 'No package lockfile found (package-lock.json / yarn.lock / pnpm-lock.yaml). Dependency versions are not reproducible.',
            file: pkgPath,
            confidence: 0.80,
        });
    }
    return findings;
}
//# sourceMappingURL=deps.js.map