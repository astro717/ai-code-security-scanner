"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.SARIF_RULE_DESCRIPTIONS = void 0;
exports.buildSARIF = buildSARIF;
const owasp_1 = require("./owasp");
// ── SARIF rule metadata ────────────────────────────────────────────────────────
// Every finding type emitted by JS/TS detectors, the Python scanner, and the Go
// scanner must have an entry below.  When adding a new detector or language
// scanner, add the corresponding rule description here AND in KNOWN_TYPES
// (reporter.ts) so SARIF output is complete and --ignore-type validation works.
exports.SARIF_RULE_DESCRIPTIONS = {
    SECRET_HARDCODED: 'Hardcoded secret or API key detected in source code.',
    SQL_INJECTION: 'User-controlled input used in a SQL query without parameterisation.',
    SHELL_INJECTION: 'User-controlled input passed to a shell execution function.',
    EVAL_INJECTION: 'User-controlled input passed to eval() or equivalent.',
    XSS: 'User-controlled value assigned to an HTML sink (e.g. innerHTML).',
    PATH_TRAVERSAL: 'User-controlled path used in a filesystem call without sanitisation.',
    PROTOTYPE_POLLUTION: 'Dynamic key assignment or Object.assign with user-controlled data.',
    INSECURE_RANDOM: 'Math.random() used in a security-sensitive context.',
    OPEN_REDIRECT: 'Redirect target derived from user-controlled input.',
    SSRF: 'HTTP request made to a URL derived from user-controlled input.',
    COMMAND_INJECTION: 'User-controlled value used as the command in a child_process call.',
    COMMAND_INJECTION_C: 'User-controlled value used as the command in a system/popen call (C/C++).',
    COMMAND_INJECTION_CS: 'User-controlled value used in Process.Start() or ProcessStartInfo (C#), enabling arbitrary command execution.',
    COMMAND_INJECTION_GO: 'User-controlled value passed to exec.Command() in Go, enabling arbitrary command execution.',
    CORS_MISCONFIGURATION: 'CORS policy allows wildcard or reflected origin with credentials.',
    JWT_HARDCODED_SECRET: 'JWT signed with a hardcoded secret literal.',
    JWT_WEAK_SECRET: 'JWT signed with a secret shorter than 32 characters.',
    JWT_NONE_ALGORITHM: 'JWT verified without an algorithm whitelist — "none" attack surface.',
    JWT_DECODE_NO_VERIFY: 'jwt.decode() used instead of jwt.verify() — signature not checked.',
    REDOS: 'RegExp constructed from user-controlled input — potential ReDoS.',
    WEAK_CRYPTO: 'Weak hashing algorithm (MD5, SHA-1) used for security purposes.',
    UNSAFE_DEPENDENCY: 'Dependency pinned to an unpinned or missing-lockfile version.',
    VULNERABLE_DEPENDENCY: 'Dependency version matches a known CVE.',
    UNSAFE_DESERIALIZATION: 'Untrusted data deserialized via pickle or equivalent — arbitrary code execution risk.',
    INSECURE_ASSERT: 'Security check implemented with assert, which is stripped in optimized mode.',
    INSECURE_BINDING: 'Server bound to 0.0.0.0, exposing the service on all network interfaces.',
    XML_INJECTION: 'XML parser configured without disabling external entities — XXE attack surface.',
    LDAP_INJECTION: 'LDAP query built with string concatenation from user-controlled input.',
    BUFFER_OVERFLOW: 'Unsafe buffer operation (gets, strcpy, sprintf, etc.) without bounds checking.',
    MASS_ASSIGNMENT: 'Mass assignment via permit(:all) or unrestricted parameter binding.',
    FORMAT_STRING: 'Non-literal format string passed to printf/fprintf family — memory read/write risk.',
    SSTI: 'Template string rendered from user-controlled input — arbitrary server-side code execution via SSTI.',
    INSECURE_SHARED_PREFS: 'Sensitive data written to Android SharedPreferences without encryption.',
    WEBVIEW_LOAD_URL: 'WebView loads a URL derived from user-controlled input — potential XSS or content injection.',
    SQL_INJECTION_CS: 'User-controlled input concatenated into a SQL query in a C# context without parameterisation.',
    PATH_TRAVERSAL_CS: 'User-controlled path used in a C# filesystem call without sanitisation or bounds checking.',
    PERFORMANCE_N_PLUS_ONE: 'ORM or database query executed inside a loop — N+1 query pattern degrades performance under load.',
    MISSING_AUTH: 'Sensitive endpoint or action reached without an authentication or authorisation check.',
    CSRF: 'State-mutating route is accessible without CSRF protection middleware.',
    UNSAFE_WEBVIEW: 'WKWebView or UIWebView configured to allow arbitrary navigation or JavaScript from untrusted origins.',
    FORCE_TRY: 'try! used in Swift — a runtime exception will crash the app if the throwing expression fails.',
    FORCE_UNWRAP: 'Force-unwrap (!) on an Optional in Swift — crashes at runtime when the value is nil.',
    UNSAFE_BLOCK: 'Swift unsafe pointer or memory block used without bounds checking or proper lifecycle management.',
};
const DOCS_BASE_URL = 'https://github.com/rouco-industries/ai-code-security-scanner#';
function buildSARIF(findings, toolName = 'ai-code-security-scanner', fixResults) {
    // Build a lookup: (file, line, type) → FixResult for fast embedding
    const fixMap = new Map();
    if (fixResults) {
        for (const r of fixResults) {
            if (!r.applied || r.fixedLine === undefined)
                continue;
            const key = `${r.file}:${r.finding.line}:${r.finding.type}`;
            fixMap.set(key, r);
        }
    }
    const rules = Array.from(new Set(findings.map((f) => f.type))).map((id) => {
        const owasp = (0, owasp_1.getOwaspCategory)(id);
        const rule = {
            id,
            name: id,
            shortDescription: { text: id },
            fullDescription: { text: exports.SARIF_RULE_DESCRIPTIONS[id] ?? id },
            helpUri: `${DOCS_BASE_URL}${id.toLowerCase().replace(/_/g, '-')}`,
        };
        if (owasp) {
            // SARIF 2.1.0 supports tags and relationships in the rule properties bag.
            // Adding the OWASP category as a tag enables tools like GitHub Advanced Security
            // to surface OWASP categories alongside rule IDs.
            rule['properties'] = {
                tags: [owasp.id],
                'owasp/id': owasp.id,
                'owasp/name': owasp.name,
                'owasp/url': owasp.url,
            };
        }
        return rule;
    });
    const results = findings.map((f) => {
        const result = {
            ruleId: f.type,
            level: f.severity === 'critical' || f.severity === 'high' ? 'error' :
                f.severity === 'medium' ? 'warning' : 'note',
            message: { text: f.message },
            locations: [
                {
                    physicalLocation: {
                        artifactLocation: { uri: f.file ?? 'unknown' },
                        region: { startLine: f.line, startColumn: f.column },
                    },
                },
            ],
        };
        // Embed SARIF 2.1.0 fix object if a dry-run fix is available for this finding
        const fixKey = `${f.file ?? 'unknown'}:${f.line}:${f.type}`;
        const fix = fixMap.get(fixKey);
        if (fix && fix.fixedLine !== undefined && fix.originalLine !== undefined) {
            result['fixes'] = [
                {
                    description: { text: fix.description },
                    artifactChanges: [
                        {
                            artifactLocation: { uri: f.file ?? 'unknown' },
                            replacements: [
                                {
                                    deletedRegion: {
                                        startLine: f.line,
                                        startColumn: 1,
                                        endLine: f.line,
                                        endColumn: fix.originalLine.length + 1,
                                    },
                                    insertedContent: { text: fix.fixedLine + '\n' },
                                },
                            ],
                        },
                    ],
                },
            ];
        }
        return result;
    });
    return {
        version: '2.1.0',
        $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
        runs: [{
                tool: {
                    driver: {
                        name: toolName,
                        version: '0.1.0',
                        informationUri: 'https://github.com/rouco-industries/ai-code-security-scanner',
                        rules,
                    },
                },
                results,
            }],
    };
}
//# sourceMappingURL=sarif.js.map