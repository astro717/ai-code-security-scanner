import { useState } from 'react'

export interface Finding {
  type: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  line: number
  column: number
  snippet: string
  message: string
  file?: string
  explanation?: string
  fixSuggestion?: string
}

export interface ScanSummaryData {
  findings: Finding[]
}

interface ScanResultsProps {
  findings: Finding[]
  onGoToLine?: (line: number) => void
}

const SEVERITY_ORDER: Finding['severity'][] = ['critical', 'high', 'medium', 'low']

// Human-readable labels and descriptions for each finding type.
// Types not listed here fall back to displaying the raw type string.
const FINDING_TYPE_META: Record<string, { label: string; description: string }> = {
  SECRET_HARDCODED:      { label: 'Hardcoded Secret',        description: 'A secret such as an API key, token, or password is hardcoded in source code.' },
  SQL_INJECTION:         { label: 'SQL Injection',           description: 'Untrusted input is interpolated directly into a SQL query, allowing database manipulation.' },
  SHELL_INJECTION:       { label: 'Shell Injection',         description: 'Untrusted input is passed to a shell command, allowing arbitrary command execution.' },
  COMMAND_INJECTION:     { label: 'Command Injection',       description: 'Dynamic values derived from user input are passed to exec/spawn without sanitization, allowing arbitrary OS command execution.' },
  COMMAND_INJECTION_C:   { label: 'Command Injection (C)',   description: 'system() or popen() called with user-controlled input in C/C++ code, allowing arbitrary OS command execution.' },
  EVAL_INJECTION:        { label: 'Eval Injection',          description: 'eval() or equivalent is called with dynamic input, allowing arbitrary code execution.' },
  XSS:                   { label: 'Cross-Site Scripting',    description: 'Untrusted data is rendered as HTML or injected into the DOM without escaping, enabling script injection.' },
  PATH_TRAVERSAL:        { label: 'Path Traversal',          description: 'User-controlled input is used in file system paths, allowing directory traversal attacks.' },
  PROTOTYPE_POLLUTION:   { label: 'Prototype Pollution',     description: 'Object properties are set from user-controlled keys, risking pollution of Object.prototype.' },
  INSECURE_RANDOM:       { label: 'Insecure Randomness',     description: 'Math.random() is used in a security-sensitive context; it is not cryptographically secure.' },
  OPEN_REDIRECT:         { label: 'Open Redirect',           description: 'A redirect URL is constructed from user input, allowing phishing via open redirect.' },
  SSRF:                  { label: 'SSRF',                    description: 'An HTTP request is made to a URL derived from user input, potentially exposing internal services.' },
  JWT_HARDCODED_SECRET:  { label: 'JWT Hardcoded Secret',    description: 'A JWT is signed with a hardcoded secret, making it trivial to forge tokens.' },
  JWT_WEAK_SECRET:       { label: 'JWT Weak Secret',         description: 'A JWT is signed with a short or guessable secret.' },
  JWT_NONE_ALGORITHM:    { label: 'JWT None Algorithm',      description: 'The JWT "none" algorithm is accepted, bypassing signature verification entirely.' },
  REDOS:                 { label: 'ReDoS',                   description: 'A regular expression with catastrophic backtracking can be exploited for denial-of-service.' },
  UNSAFE_DEPENDENCY:     { label: 'Unsafe Dependency',       description: 'A dependency is pinned to an unpinned or wildcard version, risking supply-chain attacks.' },
  VULNERABLE_DEPENDENCY: { label: 'Vulnerable Dependency',   description: 'A dependency with a known CVE is in use; upgrade to the minimum safe version.' },
  CORS_MISCONFIGURATION: { label: 'CORS Misconfiguration',   description: 'CORS is configured to allow any origin with credentials, enabling cross-site request forgery.' },
  JWT_DECODE_NO_VERIFY:  { label: 'JWT Decode No Verify',    description: 'jwt.decode() is used instead of jwt.verify(), meaning the signature is not checked and tokens can be forged.' },
  WEAK_CRYPTO:           { label: 'Weak Cryptography',       description: 'A cryptographically broken algorithm (MD5, SHA-1) is used for security-sensitive hashing or signing.' },
  BUFFER_OVERFLOW:       { label: 'Buffer Overflow',         description: 'An unsafe C/C++ buffer function (gets, strcpy, sprintf, etc.) is used without bounds checking, risking memory corruption.' },
  FORMAT_STRING:         { label: 'Format String',           description: 'A non-literal format string is passed to printf/fprintf, potentially allowing attackers to read or write arbitrary memory.' },
  MASS_ASSIGNMENT:       { label: 'Mass Assignment',         description: 'Mass assignment via permit(:all) or unrestricted parameter binding allows attackers to set arbitrary model fields.' },
  LDAP_INJECTION:        { label: 'LDAP Injection',          description: 'User-controlled input is interpolated into an LDAP query without escaping, allowing directory manipulation or auth bypass.' },
  XML_INJECTION:         { label: 'XML Injection (XXE)',     description: 'The XML parser is configured without disabling external entities, allowing XXE attacks that can read local files or trigger SSRF.' },
  INSECURE_ASSERT:       { label: 'Insecure Assert',         description: 'A security check is implemented with assert(), which is silently stripped in optimized/production mode.' },
  INSECURE_BINDING:      { label: 'Insecure Binding',        description: 'The server is bound to 0.0.0.0, exposing the service on all network interfaces including external ones.' },
  UNSAFE_DESERIALIZATION:{ label: 'Unsafe Deserialization',  description: 'Untrusted data is deserialized via pickle or equivalent, enabling arbitrary code execution on the server.' },
}

// OWASP Top 10 2021 mapping — mirrors src/scanner/owasp.ts FINDING_TO_OWASP
const FINDING_TO_OWASP: Record<string, { id: string; name: string }> = {
  OPEN_REDIRECT:         { id: 'A01:2021', name: 'Broken Access Control' },
  PATH_TRAVERSAL:        { id: 'A01:2021', name: 'Broken Access Control' },
  MASS_ASSIGNMENT:       { id: 'A01:2021', name: 'Broken Access Control' },
  WEAK_CRYPTO:           { id: 'A02:2021', name: 'Cryptographic Failures' },
  INSECURE_RANDOM:       { id: 'A02:2021', name: 'Cryptographic Failures' },
  JWT_WEAK_SECRET:       { id: 'A02:2021', name: 'Cryptographic Failures' },
  JWT_HARDCODED_SECRET:  { id: 'A02:2021', name: 'Cryptographic Failures' },
  SECRET_HARDCODED:      { id: 'A02:2021', name: 'Cryptographic Failures' },
  SQL_INJECTION:         { id: 'A03:2021', name: 'Injection' },
  COMMAND_INJECTION:     { id: 'A03:2021', name: 'Injection' },
  COMMAND_INJECTION_C:   { id: 'A03:2021', name: 'Injection' },
  SHELL_INJECTION:       { id: 'A03:2021', name: 'Injection' },
  EVAL_INJECTION:        { id: 'A03:2021', name: 'Injection' },
  XSS:                   { id: 'A03:2021', name: 'Injection' },
  LDAP_INJECTION:        { id: 'A03:2021', name: 'Injection' },
  XML_INJECTION:         { id: 'A03:2021', name: 'Injection' },
  FORMAT_STRING:         { id: 'A03:2021', name: 'Injection' },
  PROTOTYPE_POLLUTION:   { id: 'A03:2021', name: 'Injection' },
  REDOS:                 { id: 'A04:2021', name: 'Insecure Design' },
  INSECURE_BINDING:      { id: 'A04:2021', name: 'Insecure Design' },
  CORS_MISCONFIGURATION: { id: 'A04:2021', name: 'Insecure Design' },
  BUFFER_OVERFLOW:       { id: 'A04:2021', name: 'Insecure Design' },
  INSECURE_ASSERT:       { id: 'A04:2021', name: 'Insecure Design' },
  JWT_NONE_ALGORITHM:    { id: 'A05:2021', name: 'Security Misconfiguration' },
  UNSAFE_DEPENDENCY:     { id: 'A06:2021', name: 'Vulnerable Components' },
  VULNERABLE_DEPENDENCY: { id: 'A06:2021', name: 'Vulnerable Components' },
  JWT_DECODE_NO_VERIFY:  { id: 'A07:2021', name: 'Auth Failures' },
  UNSAFE_DESERIALIZATION:{ id: 'A08:2021', name: 'Integrity Failures' },
  SSRF:                  { id: 'A10:2021', name: 'SSRF' },
}

// OWASP Top 10 2021 documentation URLs
const OWASP_URLS: Record<string, string> = {
  'A01:2021': 'https://owasp.org/Top10/A01_2021-Broken_Access_Control/',
  'A02:2021': 'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/',
  'A03:2021': 'https://owasp.org/Top10/A03_2021-Injection/',
  'A04:2021': 'https://owasp.org/Top10/A04_2021-Insecure_Design/',
  'A05:2021': 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/',
  'A06:2021': 'https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/',
  'A07:2021': 'https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/',
  'A08:2021': 'https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/',
  'A09:2021': 'https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/',
  'A10:2021': 'https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_(SSRF)/',
}

const SEVERITY_STYLES: Record<string, { badge: string; border: string; sectionBg: string; label: string }> = {
  critical: {
    badge: 'bg-red-500/20 text-red-400 border-red-500/40',
    border: 'border-red-500/20',
    sectionBg: 'bg-red-500/5 border-red-500/20',
    label: 'Critical',
  },
  high: {
    badge: 'bg-orange-500/20 text-orange-400 border-orange-500/40',
    border: 'border-orange-500/20',
    sectionBg: 'bg-orange-500/5 border-orange-500/20',
    label: 'High',
  },
  medium: {
    badge: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/40',
    border: 'border-yellow-500/20',
    sectionBg: 'bg-yellow-500/5 border-yellow-500/20',
    label: 'Medium',
  },
  low: {
    badge: 'bg-gray-500/20 text-gray-400 border-gray-500/40',
    border: 'border-gray-500/20',
    sectionBg: 'bg-gray-500/5 border-gray-500/20',
    label: 'Low',
  },
}

function AiInsightBlock({ explanation, fixSuggestion }: { explanation?: string; fixSuggestion?: string }) {
  const [expanded, setExpanded] = useState(false)

  return (
    <div className="border border-violet-500/20 rounded-lg overflow-hidden">
      <button
        type="button"
        onClick={() => setExpanded((v) => !v)}
        className="w-full flex items-center gap-2 px-3 py-1.5 bg-violet-500/5 hover:bg-violet-500/10 transition-colors text-left"
      >
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="text-violet-400 shrink-0" aria-hidden="true">
          <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2" />
        </svg>
        <span className="text-xs font-mono text-violet-400 font-medium flex-1">AI Insight</span>
        <svg
          width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"
          className={`text-violet-400/60 transition-transform ${expanded ? 'rotate-180' : ''}`}
          aria-hidden="true"
        >
          <polyline points="6 9 12 15 18 9" />
        </svg>
      </button>

      {expanded && (
        <div className="px-3 py-2 flex flex-col gap-2 bg-[#0d0d14]">
          {explanation && (
            <p className="text-xs text-[#c9d1d9] leading-relaxed">{explanation}</p>
          )}
          {fixSuggestion && (
            <div>
              <span className="text-xs font-mono text-violet-400/70 uppercase tracking-wide text-[10px]">Suggested Fix</span>
              <code
                className="block text-xs font-mono bg-[#161b22] rounded px-3 py-2 text-[#7ee787] overflow-x-auto whitespace-pre mt-1"
                style={{ fontFamily: '"JetBrains Mono", "Fira Code", monospace' }}
              >
                {fixSuggestion}
              </code>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

function EmptyState() {
  return (
    <div className="flex flex-col items-center justify-center py-12 gap-3">
      <div className="rounded-full bg-green-500/10 p-4 border border-green-500/20">
        <svg
          width="32"
          height="32"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="2"
          strokeLinecap="round"
          strokeLinejoin="round"
          className="text-green-500"
          aria-hidden="true"
        >
          <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14" />
          <polyline points="22 4 12 14.01 9 11.01" />
        </svg>
      </div>
      <p className="text-sm font-medium text-green-400">No vulnerabilities detected</p>
      <p className="text-xs text-[#7d8590]">Your code looks clean — good job.</p>
    </div>
  )
}

type SeverityFilter = 'all' | Finding['severity']

const FILTER_OPTIONS: { value: SeverityFilter; label: string }[] = [
  { value: 'all', label: 'All' },
  { value: 'critical', label: 'Critical' },
  { value: 'high', label: 'High' },
  { value: 'medium', label: 'Medium' },
  { value: 'low', label: 'Low' },
]

const FILTER_STYLES: Record<SeverityFilter, { active: string; inactive: string }> = {
  all:      { active: 'bg-[#30363d] text-white border-[#6e7681]', inactive: 'text-[#7d8590] border-[#30363d] hover:border-[#6e7681] hover:text-[#c9d1d9]' },
  critical: { active: 'bg-red-500/20 text-red-400 border-red-500/40', inactive: 'text-[#7d8590] border-[#30363d] hover:border-red-500/30 hover:text-red-400' },
  high:     { active: 'bg-orange-500/20 text-orange-400 border-orange-500/40', inactive: 'text-[#7d8590] border-[#30363d] hover:border-orange-500/30 hover:text-orange-400' },
  medium:   { active: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/40', inactive: 'text-[#7d8590] border-[#30363d] hover:border-yellow-500/30 hover:text-yellow-400' },
  low:      { active: 'bg-gray-500/20 text-gray-400 border-gray-500/40', inactive: 'text-[#7d8590] border-[#30363d] hover:border-gray-500/30 hover:text-gray-400' },
}

export function ScanResults({ findings, onGoToLine }: ScanResultsProps) {
  const [collapsedGroups, setCollapsedGroups] = useState<Set<string>>(new Set())
  const [severityFilter, setSeverityFilter] = useState<SeverityFilter>('all')

  if (findings.length === 0) {
    return <EmptyState />
  }

  const visibleFindings = severityFilter === 'all'
    ? findings
    : findings.filter((f) => f.severity === severityFilter)

  // Count per severity for filter button badges
  const counts: Record<Finding['severity'], number> = { critical: 0, high: 0, medium: 0, low: 0 }
  for (const f of findings) counts[f.severity]++

  // Group by severity in fixed order
  const grouped: Record<string, Finding[]> = {}
  for (const sev of SEVERITY_ORDER) {
    const group = visibleFindings.filter((f) => f.severity === sev)
    if (group.length > 0) grouped[sev] = group
  }

  const toggleGroup = (sev: string) => {
    setCollapsedGroups((prev) => {
      const next = new Set(prev)
      if (next.has(sev)) next.delete(sev)
      else next.add(sev)
      return next
    })
  }

  let cardIndex = 0

  return (
    <div className="flex flex-col gap-4">
      {/* OWASP Top 10 2021 breakdown panel */}
      {(() => {
        const owaspCounts: Record<string, { name: string; count: number }> = {}
        for (const f of findings) {
          const cat = FINDING_TO_OWASP[f.type]
          if (!cat) continue
          if (!owaspCounts[cat.id]) owaspCounts[cat.id] = { name: cat.name, count: 0 }
          owaspCounts[cat.id]!.count++
        }
        const owaspEntries = Object.entries(owaspCounts).sort((a, b) => b[1].count - a[1].count)
        if (owaspEntries.length === 0) return null
        return (
          <div className="border border-[#1e1e2e] rounded-lg overflow-hidden">
            <div className="px-3 py-2 bg-[#0d1117] border-b border-[#1e1e2e] flex items-center gap-2">
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="text-[#7d8590]" aria-hidden="true">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
              </svg>
              <span className="text-xs font-mono text-[#7d8590] uppercase tracking-widest">OWASP Top 10 Breakdown</span>
            </div>
            <div className="divide-y divide-[#1e1e2e]">
              {owaspEntries.map(([id, { name, count }]) => {
                const url = OWASP_URLS[id] ?? '#'
                const pct = Math.round((count / findings.length) * 100)
                return (
                  <div key={id} className="flex items-center gap-3 px-3 py-2">
                    <a
                      href={url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-xs font-mono text-violet-400 hover:text-violet-300 transition-colors shrink-0 w-20"
                      title={`${id} — click to open OWASP docs`}
                    >
                      {id.split(':')[0]}
                    </a>
                    <span className="text-xs text-[#7d8590] font-mono flex-1 truncate">{name}</span>
                    <div className="flex items-center gap-2 shrink-0">
                      <div className="w-20 h-1.5 bg-[#1e1e2e] rounded-full overflow-hidden">
                        <div className="h-full bg-violet-500/60 rounded-full" style={{ width: `${pct}%` }} />
                      </div>
                      <span className="text-xs font-mono text-[#4a5668] w-6 text-right">{count}</span>
                    </div>
                  </div>
                )
              })}
            </div>
          </div>
        )
      })()}

            {/* Severity filter bar */}
      <div className="flex items-center gap-2 flex-wrap">
        {FILTER_OPTIONS.map(({ value, label }) => {
          const isActive = severityFilter === value
          const style = FILTER_STYLES[value]
          const count = value === 'all' ? findings.length : counts[value as Finding['severity']]
          return (
            <button
              key={value}
              type="button"
              onClick={() => setSeverityFilter(value)}
              className={`flex items-center gap-1.5 px-2.5 py-1 rounded border text-xs font-mono font-medium transition-colors ${isActive ? style.active : style.inactive}`}
            >
              {label}
              {count > 0 && (
                <span className="opacity-70">{count}</span>
              )}
            </button>
          )
        })}
        {severityFilter !== 'all' && visibleFindings.length === 0 && (
          <span className="text-xs text-[#7d8590] ml-2">No {severityFilter} findings</span>
        )}
      </div>

      {Object.entries(grouped).map(([sev, items]) => {
        const styles = SEVERITY_STYLES[sev] ?? SEVERITY_STYLES.low
        const isCollapsed = collapsedGroups.has(sev)

        return (
          <div key={sev} className={`rounded-lg border ${styles.sectionBg}`}>
            {/* Section header */}
            <button
              type="button"
              onClick={() => toggleGroup(sev)}
              className="w-full flex items-center justify-between px-3 py-2 text-left hover:opacity-80 transition-opacity"
            >
              <div className="flex items-center gap-2">
                <svg
                  width="10"
                  height="10"
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="2"
                  className={`transition-transform ${isCollapsed ? '-rotate-90' : ''}`}
                  aria-hidden="true"
                >
                  <polyline points="6 9 12 15 18 9" />
                </svg>
                <span className={`px-2 py-0.5 text-xs rounded border font-mono font-semibold uppercase tracking-wide ${styles.badge}`}>
                  {styles.label}
                </span>
              </div>
              <span className="text-xs text-[#7d8590] font-mono">{items.length} issue{items.length !== 1 ? 's' : ''}</span>
            </button>

            {!isCollapsed && (
              <div className="flex flex-col gap-1.5 px-2 pb-2">
                {items.map((finding, i) => {
                  const animDelay = cardIndex++ * 40

                  return (
                    <div
                      key={i}
                      className={`rounded-lg border bg-[#111118] p-3 flex flex-col gap-2 ${styles.border}`}
                      style={{ animation: `fadeIn 0.15s ease ${animDelay}ms both` }}
                    >
                      {/* Header row */}
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="text-xs font-mono text-[#7d8590]" title={FINDING_TYPE_META[finding.type]?.description ?? finding.type}>
                          {FINDING_TYPE_META[finding.type]?.label ?? finding.type}
                        </span>
                        {FINDING_TO_OWASP[finding.type] && (
                          <a
                            href={OWASP_URLS[FINDING_TO_OWASP[finding.type].id] ?? '#'}
                            target="_blank"
                            rel="noopener noreferrer"
                            title={`${FINDING_TO_OWASP[finding.type].id} — ${FINDING_TO_OWASP[finding.type].name} (click to view OWASP docs)`}
                            className="text-[10px] font-mono font-semibold text-blue-400 bg-blue-500/15 border border-blue-500/30 px-1.5 py-0.5 rounded hover:bg-blue-500/25 hover:border-blue-500/50 transition-colors no-underline"
                            onClick={(e) => e.stopPropagation()}
                          >
                            {FINDING_TO_OWASP[finding.type].id}
                          </a>
                        )}
                        {finding.file && (
                          <span className="text-xs text-[#7d8590] font-mono truncate max-w-[120px]">{finding.file}</span>
                        )}
                        <div className="ml-auto flex items-center gap-1.5">
                          <span className="text-xs text-[#7d8590] font-mono whitespace-nowrap">
                            L{finding.line}:{finding.column}
                          </span>
                          {onGoToLine && finding.line > 0 && (
                            <button
                              type="button"
                              onClick={() => onGoToLine(finding.line)}
                              title={`Go to line ${finding.line}`}
                              className="flex items-center gap-1 px-1.5 py-0.5 text-xs font-mono rounded border border-[#30363d] text-[#7d8590] hover:border-violet-500/60 hover:text-violet-400 transition-colors"
                            >
                              <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true">
                                <line x1="12" y1="5" x2="12" y2="19" /><polyline points="19 12 12 19 5 12" />
                              </svg>
                              Go to line
                            </button>
                          )}
                        </div>
                      </div>

                      {/* Code snippet */}
                      <code
                        className="block text-xs font-mono bg-[#0d1117] rounded px-3 py-2 text-[#e6edf3] overflow-x-auto whitespace-pre"
                        style={{ fontFamily: '"JetBrains Mono", "Fira Code", monospace' }}
                      >
                        {finding.snippet}
                      </code>

                      {/* Description */}
                      <p className="text-xs text-[#7d8590] leading-relaxed">{finding.message}</p>

                      {/* AI explanation / fix suggestion */}
                      {(finding.explanation || finding.fixSuggestion) && (
                        <AiInsightBlock explanation={finding.explanation} fixSuggestion={finding.fixSuggestion} />
                      )}
                    </div>
                  )
                })}
              </div>
            )}
          </div>
        )
      })}

      <style>{`
        @keyframes fadeIn {
          from { opacity: 0; transform: translateY(6px); }
          to   { opacity: 1; transform: translateY(0); }
        }
      `}</style>
    </div>
  )
}
