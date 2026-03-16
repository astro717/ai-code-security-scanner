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

export function ScanResults({ findings, onGoToLine }: ScanResultsProps) {
  const [collapsedGroups, setCollapsedGroups] = useState<Set<string>>(new Set())

  if (findings.length === 0) {
    return <EmptyState />
  }

  // Group by severity in fixed order
  const grouped: Record<string, Finding[]> = {}
  for (const sev of SEVERITY_ORDER) {
    const group = findings.filter((f) => f.severity === sev)
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
                        <span className="text-xs font-mono text-[#7d8590]">{finding.type}</span>
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
