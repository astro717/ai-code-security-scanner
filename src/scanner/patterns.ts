export type Severity = 'critical' | 'high' | 'medium' | 'low';

export interface VulnerabilityPattern {
  id: string;
  name: string;
  severity: Severity;
  description: string;
  remediation: string;
}

export const VULNERABILITY_PATTERNS: Record<string, VulnerabilityPattern> = {
  COMMAND_INJECTION: {
    id: 'COMMAND_INJECTION',
    name: 'Command Injection',
    severity: 'critical',
    description: 'User-controlled value used as the command in a child_process call.',
    remediation: 'Use execFile with explicit argument arrays instead of exec/spawn with shell.',
  },
  CORS_MISCONFIGURATION: {
    id: 'CORS_MISCONFIGURATION',
    name: 'CORS Misconfiguration',
    severity: 'medium',
    description: 'CORS policy allows wildcard or reflected origin with credentials.',
    remediation: 'Restrict allowed origins to a known whitelist and disable credentials for wildcard.',
  },
  EVAL_INJECTION: {
    id: 'EVAL_INJECTION',
    name: 'Eval with Dynamic Input',
    severity: 'high',
    description: 'eval() or equivalent executed with a non-literal argument.',
    remediation: 'Avoid eval(); use JSON.parse() or safe alternatives.',
  },
  INSECURE_RANDOM: {
    id: 'INSECURE_RANDOM',
    name: 'Insecure Random',
    severity: 'medium',
    description: 'Math.random() used in a security-sensitive context.',
    remediation: 'Use crypto.randomBytes() or crypto.getRandomValues() for security purposes.',
  },
  JWT_DECODE_NO_VERIFY: {
    id: 'JWT_DECODE_NO_VERIFY',
    name: 'JWT Decode Without Verification',
    severity: 'high',
    description: 'jwt.decode() used instead of jwt.verify() — signature not checked.',
    remediation: 'Use jwt.verify() with a secret/key to validate the token signature.',
  },
  JWT_HARDCODED_SECRET: {
    id: 'JWT_HARDCODED_SECRET',
    name: 'JWT Hardcoded Secret',
    severity: 'critical',
    description: 'JWT signed with a hardcoded secret literal.',
    remediation: 'Store JWT secrets in environment variables or a secrets manager.',
  },
  JWT_NONE_ALGORITHM: {
    id: 'JWT_NONE_ALGORITHM',
    name: 'JWT None Algorithm',
    severity: 'critical',
    description: 'JWT verified without an algorithm whitelist — "none" attack surface.',
    remediation: 'Always specify an explicit algorithms whitelist in jwt.verify() options.',
  },
  JWT_WEAK_SECRET: {
    id: 'JWT_WEAK_SECRET',
    name: 'JWT Weak Secret',
    severity: 'high',
    description: 'JWT signed with a secret shorter than 32 characters.',
    remediation: 'Use a secret of at least 32 characters, ideally 64+ random bytes.',
  },
  OPEN_REDIRECT: {
    id: 'OPEN_REDIRECT',
    name: 'Open Redirect',
    severity: 'medium',
    description: 'Redirect target derived from user-controlled input.',
    remediation: 'Validate redirect URLs against a whitelist of allowed destinations.',
  },
  PATH_TRAVERSAL: {
    id: 'PATH_TRAVERSAL',
    name: 'Path Traversal',
    severity: 'high',
    description: 'User-controlled path used in a filesystem call without sanitisation.',
    remediation: 'Resolve and validate paths against a known safe root directory.',
  },
  PROTOTYPE_POLLUTION: {
    id: 'PROTOTYPE_POLLUTION',
    name: 'Prototype Pollution',
    severity: 'high',
    description: 'Dynamic key assignment or Object.assign with user-controlled data.',
    remediation: 'Use Map instead of plain objects, or validate keys against a whitelist.',
  },
  REDOS: {
    id: 'REDOS',
    name: 'Regular Expression DoS',
    severity: 'medium',
    description: 'RegExp constructed from user-controlled input — potential ReDoS.',
    remediation: 'Avoid constructing RegExp from user input; use a safe regex library.',
  },
  SECRET_HARDCODED: {
    id: 'SECRET_HARDCODED',
    name: 'Hardcoded Secret',
    severity: 'critical',
    description: 'Sensitive credentials or API keys hardcoded in source code.',
    remediation: 'Use environment variables or a secrets manager instead.',
  },
  SHELL_INJECTION: {
    id: 'SHELL_INJECTION',
    name: 'Shell Injection',
    severity: 'high',
    description: 'Shell command constructed with unsanitized user input.',
    remediation: 'Avoid shell interpolation; use execFile with argument arrays.',
  },
  SQL_INJECTION: {
    id: 'SQL_INJECTION',
    name: 'SQL Injection',
    severity: 'critical',
    description: 'User input concatenated into a SQL query without sanitization.',
    remediation: 'Use parameterized queries or prepared statements.',
  },
  SSRF: {
    id: 'SSRF',
    name: 'Server-Side Request Forgery',
    severity: 'high',
    description: 'HTTP request made to a URL derived from user-controlled input.',
    remediation: 'Validate URLs against an allowlist and block internal/private IP ranges.',
  },
  UNSAFE_DEPENDENCY: {
    id: 'UNSAFE_DEPENDENCY',
    name: 'Unsafe Dependency Version',
    severity: 'medium',
    description: 'Dependency pinned to latest/* or missing lockfile.',
    remediation: 'Pin to a specific version and commit package-lock.json.',
  },
  VULNERABLE_DEPENDENCY: {
    id: 'VULNERABLE_DEPENDENCY',
    name: 'Vulnerable Dependency',
    severity: 'high',
    description: 'Dependency version matches a known CVE.',
    remediation: 'Upgrade to the minimum safe version indicated in the finding message.',
  },
  WEAK_CRYPTO: {
    id: 'WEAK_CRYPTO',
    name: 'Weak Cryptography',
    severity: 'medium',
    description: 'Weak hashing algorithm (MD5, SHA-1) used for security purposes.',
    remediation: 'Use SHA-256 or stronger hashing algorithms for security-sensitive operations.',
  },
  XSS: {
    id: 'XSS',
    name: 'Cross-Site Scripting',
    severity: 'high',
    description: 'User-controlled value assigned to an HTML sink (e.g. innerHTML).',
    remediation: 'Sanitize user input before rendering; use textContent instead of innerHTML.',
  },
  UNSAFE_DESERIALIZATION: {
    id: 'UNSAFE_DESERIALIZATION',
    name: 'Unsafe Deserialization',
    severity: 'critical',
    description: 'Untrusted data deserialized via pickle or equivalent — arbitrary code execution risk.',
    remediation: 'Use safe serialization formats (JSON) or validate input before deserializing.',
  },
  INSECURE_ASSERT: {
    id: 'INSECURE_ASSERT',
    name: 'Insecure Assert',
    severity: 'medium',
    description: 'Security check implemented with assert, which is stripped in optimized mode.',
    remediation: 'Replace assert with explicit conditional checks that raise exceptions.',
  },
  INSECURE_BINDING: {
    id: 'INSECURE_BINDING',
    name: 'Insecure Network Binding',
    severity: 'medium',
    description: 'Server bound to 0.0.0.0, exposing the service on all network interfaces.',
    remediation: 'Bind to 127.0.0.1 or a specific interface unless public access is intended.',
  },
  XML_INJECTION: {
    id: 'XML_INJECTION',
    name: 'XML External Entity Injection',
    severity: 'high',
    description: 'XML parser configured without disabling external entities — XXE attack surface.',
    remediation: 'Disable external entity processing and DTD loading in the XML parser configuration.',
  },
  LDAP_INJECTION: {
    id: 'LDAP_INJECTION',
    name: 'LDAP Injection',
    severity: 'high',
    description: 'LDAP query built with string concatenation from user-controlled input.',
    remediation: 'Use parameterized LDAP queries or escape special characters in user input.',
  },
  BUFFER_OVERFLOW: {
    id: 'BUFFER_OVERFLOW',
    name: 'Buffer Overflow',
    severity: 'critical',
    description: 'Unsafe buffer operation (gets, strcpy, sprintf, etc.) without bounds checking.',
    remediation: 'Use bounds-checked alternatives (fgets, strncpy, snprintf) with explicit size limits.',
  },
  MASS_ASSIGNMENT: {
    id: 'MASS_ASSIGNMENT',
    name: 'Mass Assignment',
    severity: 'high',
    description: 'Mass assignment via permit(:all) or unrestricted parameter binding.',
    remediation: 'Explicitly whitelist permitted attributes in strong parameter definitions.',
  },
  FORMAT_STRING: {
    id: 'FORMAT_STRING',
    name: 'Format String Vulnerability',
    severity: 'critical',
    description: 'Non-literal format string passed to printf/fprintf family — memory read/write risk.',
    remediation: 'Always use a string literal as the format argument to printf-family functions.',
  },
  CSRF: {
    id: 'CSRF',
    name: 'Cross-Site Request Forgery',
    severity: 'high',
    description: 'CSRF protection is disabled or missing on a state-changing endpoint.',
    remediation:
      'For Express: use the csurf middleware on POST/PUT/DELETE routes. ' +
      'For Django: remove @csrf_exempt and rely on the built-in CSRF middleware. ' +
      'For Flask: enable CSRFProtect from Flask-WTF and set WTF_CSRF_ENABLED = True.',
  },
};
