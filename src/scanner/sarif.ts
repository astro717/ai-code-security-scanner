import { Finding } from './reporter';
import { getOwaspCategory } from './owasp';

// ── SARIF rule metadata ────────────────────────────────────────────────────────

// Every finding type emitted by JS/TS detectors, the Python scanner, and the Go
// scanner must have an entry below.  When adding a new detector or language
// scanner, add the corresponding rule description here AND in KNOWN_TYPES
// (reporter.ts) so SARIF output is complete and --ignore-type validation works.
export const SARIF_RULE_DESCRIPTIONS: Record<string, string> = {
  SECRET_HARDCODED:      'Hardcoded secret or API key detected in source code.',
  SQL_INJECTION:         'User-controlled input used in a SQL query without parameterisation.',
  SHELL_INJECTION:       'User-controlled input passed to a shell execution function.',
  EVAL_INJECTION:        'User-controlled input passed to eval() or equivalent.',
  XSS:                   'User-controlled value assigned to an HTML sink (e.g. innerHTML).',
  PATH_TRAVERSAL:        'User-controlled path used in a filesystem call without sanitisation.',
  PROTOTYPE_POLLUTION:   'Dynamic key assignment or Object.assign with user-controlled data.',
  INSECURE_RANDOM:       'Math.random() used in a security-sensitive context.',
  OPEN_REDIRECT:         'Redirect target derived from user-controlled input.',
  SSRF:                  'HTTP request made to a URL derived from user-controlled input.',
  COMMAND_INJECTION:     'User-controlled value used as the command in a child_process call.',
  COMMAND_INJECTION_C:   'User-controlled value used as the command in a system/popen call (C/C++).',
  CORS_MISCONFIGURATION: 'CORS policy allows wildcard or reflected origin with credentials.',
  JWT_HARDCODED_SECRET:  'JWT signed with a hardcoded secret literal.',
  JWT_WEAK_SECRET:       'JWT signed with a secret shorter than 32 characters.',
  JWT_NONE_ALGORITHM:    'JWT verified without an algorithm whitelist — "none" attack surface.',
  JWT_DECODE_NO_VERIFY:  'jwt.decode() used instead of jwt.verify() — signature not checked.',
  REDOS:                 'RegExp constructed from user-controlled input — potential ReDoS.',
  WEAK_CRYPTO:           'Weak hashing algorithm (MD5, SHA-1) used for security purposes.',
  UNSAFE_DEPENDENCY:     'Dependency pinned to an unpinned or missing-lockfile version.',
  VULNERABLE_DEPENDENCY: 'Dependency version matches a known CVE.',
  UNSAFE_DESERIALIZATION:'Untrusted data deserialized via pickle or equivalent — arbitrary code execution risk.',
  INSECURE_ASSERT:       'Security check implemented with assert, which is stripped in optimized mode.',
  INSECURE_BINDING:      'Server bound to 0.0.0.0, exposing the service on all network interfaces.',
  XML_INJECTION:         'XML parser configured without disabling external entities — XXE attack surface.',
  LDAP_INJECTION:        'LDAP query built with string concatenation from user-controlled input.',
  BUFFER_OVERFLOW:       'Unsafe buffer operation (gets, strcpy, sprintf, etc.) without bounds checking.',
  MASS_ASSIGNMENT:       'Mass assignment via permit(:all) or unrestricted parameter binding.',
  FORMAT_STRING:         'Non-literal format string passed to printf/fprintf family — memory read/write risk.',
};

const DOCS_BASE_URL = 'https://github.com/rouco-industries/ai-code-security-scanner#';

export function buildSARIF(findings: Finding[], toolName = 'ai-code-security-scanner'): object {
  const rules = Array.from(new Set(findings.map((f) => f.type))).map((id) => {
    const owasp = getOwaspCategory(id);
    const rule: Record<string, unknown> = {
      id,
      name: id,
      shortDescription: { text: id },
      fullDescription: { text: SARIF_RULE_DESCRIPTIONS[id] ?? id },
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

  const results = findings.map((f) => ({
    ruleId: f.type,
    level:
      f.severity === 'critical' || f.severity === 'high' ? 'error' :
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
  }));

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
