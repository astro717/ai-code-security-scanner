/**
 * OWASP Top 10 2021 classification for every finding type emitted by the scanner.
 *
 * Reference: https://owasp.org/Top10/
 *
 * Each entry maps a finding-type string to its primary OWASP 2021 category.
 * Not every vulnerability maps 1-to-1 (e.g. Hardcoded Secret is A02 Cryptographic
 * Failures but also touches A07 Identification).  The category chosen is the most
 * directly applicable one per OWASP's own mapping guidance.
 */

export interface OwaspCategory {
  /** OWASP identifier, e.g. "A03:2021" */
  id: string;
  /** Short human-readable name */
  name: string;
  /** Full OWASP description URL */
  url: string;
}

export const OWASP_CATEGORIES: Record<string, OwaspCategory> = {
  'A01:2021': {
    id: 'A01:2021',
    name: 'Broken Access Control',
    url: 'https://owasp.org/Top10/A01_2021-Broken_Access_Control/',
  },
  'A02:2021': {
    id: 'A02:2021',
    name: 'Cryptographic Failures',
    url: 'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/',
  },
  'A03:2021': {
    id: 'A03:2021',
    name: 'Injection',
    url: 'https://owasp.org/Top10/A03_2021-Injection/',
  },
  'A04:2021': {
    id: 'A04:2021',
    name: 'Insecure Design',
    url: 'https://owasp.org/Top10/A04_2021-Insecure_Design/',
  },
  'A05:2021': {
    id: 'A05:2021',
    name: 'Security Misconfiguration',
    url: 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/',
  },
  'A06:2021': {
    id: 'A06:2021',
    name: 'Vulnerable and Outdated Components',
    url: 'https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/',
  },
  'A07:2021': {
    id: 'A07:2021',
    name: 'Identification and Authentication Failures',
    url: 'https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/',
  },
  'A08:2021': {
    id: 'A08:2021',
    name: 'Software and Data Integrity Failures',
    url: 'https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/',
  },
  'A09:2021': {
    id: 'A09:2021',
    name: 'Security Logging and Monitoring Failures',
    url: 'https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/',
  },
  'A10:2021': {
    id: 'A10:2021',
    name: 'Server-Side Request Forgery',
    url: 'https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_(SSRF)/',
  },
};

/**
 * Maps each scanner finding type to its primary OWASP Top 10 2021 category ID.
 */
export const FINDING_TO_OWASP: Record<string, string> = {
  // A01 — Broken Access Control
  OPEN_REDIRECT:          'A01:2021',
  PATH_TRAVERSAL:         'A01:2021',
  PATH_TRAVERSAL_CS:      'A01:2021',
  MASS_ASSIGNMENT:        'A01:2021',

  // A02 — Cryptographic Failures
  WEAK_CRYPTO:            'A02:2021',
  INSECURE_RANDOM:        'A02:2021',
  JWT_WEAK_SECRET:        'A02:2021',
  JWT_HARDCODED_SECRET:   'A02:2021',
  SECRET_HARDCODED:       'A02:2021',

  // A03 — Injection
  SQL_INJECTION:          'A03:2021',
  COMMAND_INJECTION:      'A03:2021',
  COMMAND_INJECTION_C:    'A03:2021',
  COMMAND_INJECTION_CS:   'A03:2021',
  SHELL_INJECTION:        'A03:2021',
  EVAL_INJECTION:         'A03:2021',
  XSS:                    'A03:2021',
  LDAP_INJECTION:         'A03:2021',
  XML_INJECTION:          'A03:2021',
  FORMAT_STRING:          'A03:2021',
  SSTI:                   'A03:2021',
  PROTOTYPE_POLLUTION:    'A03:2021',

  // A04 — Insecure Design
  REDOS:                  'A04:2021',
  INSECURE_BINDING:       'A04:2021',
  CORS_MISCONFIGURATION:  'A04:2021',
  BUFFER_OVERFLOW:        'A04:2021',
  INSECURE_ASSERT:        'A04:2021',
  PERFORMANCE_N_PLUS_ONE: 'A04:2021',
  INSECURE_SHARED_PREFS:  'A04:2021',

  // A05 — Security Misconfiguration
  JWT_NONE_ALGORITHM:     'A05:2021',

  // A06 — Vulnerable and Outdated Components
  UNSAFE_DEPENDENCY:      'A06:2021',
  VULNERABLE_DEPENDENCY:  'A06:2021',

  // A07 — Identification and Authentication Failures
  JWT_DECODE_NO_VERIFY:   'A07:2021',

  // A08 — Software and Data Integrity Failures
  UNSAFE_DESERIALIZATION: 'A08:2021',

  // A10 — SSRF
  SSRF:                   'A10:2021',

  // Additional types — Kotlin / Android
  SQL_INJECTION_CS:       'A03:2021',
  WEBVIEW_LOAD_URL:       'A03:2021',
};

/**
 * Returns the resolved OwaspCategory for a given finding type, or undefined if
 * the type has no OWASP mapping.
 */
export function getOwaspCategory(findingType: string): OwaspCategory | undefined {
  const id = FINDING_TO_OWASP[findingType];
  return id ? OWASP_CATEGORIES[id] : undefined;
}
