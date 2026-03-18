import { useState, useRef, useEffect, useCallback } from 'react'
import { CodeEditor, type CodeEditorHandle } from './components/CodeEditor'
import { ScanResults, type Finding } from './components/ScanResults'
import { SummaryCards, type ScanSummary } from './components/SummaryCards'

type ScanStatus = 'idle' | 'loading' | 'success' | 'error'
type EditorTab = 'editor' | 'repo'

type Severity = 'critical' | 'high' | 'medium' | 'low'

function topSeverity(findings: { severity: string }[]): Severity | null {
  const order: Severity[] = ['critical', 'high', 'medium', 'low']
  for (const s of order) {
    if (findings.some((f) => f.severity === s)) return s
  }
  return null
}

const severityBadgeClass: Record<Severity, string> = {
  critical: 'bg-red-500/20 text-red-400 border-red-500/40',
  high:     'bg-orange-500/20 text-orange-400 border-orange-500/40',
  medium:   'bg-yellow-500/20 text-yellow-400 border-yellow-500/40',
  low:      'bg-gray-500/20 text-gray-400 border-gray-500/40',
}

// ── Scan history ──────────────────────────────────────────────────────────────

const HISTORY_KEY = 'ai-sec-scanner-history'
const HISTORY_MAX = 10

interface ScanHistoryEntry {
  id: string
  timestamp: string
  source: string // filename or repo URL
  summary: ScanSummary
  findings: Finding[]
  code?: string // editor code (only for editor scans)
}

function loadHistory(): ScanHistoryEntry[] {
  try {
    const raw = localStorage.getItem(HISTORY_KEY)
    if (!raw) return []
    return JSON.parse(raw) as ScanHistoryEntry[]
  } catch {
    return []
  }
}

function saveHistory(entries: ScanHistoryEntry[]): void {
  try {
    localStorage.setItem(HISTORY_KEY, JSON.stringify(entries.slice(0, HISTORY_MAX)))
  } catch {
    // Quota exceeded — silently ignore
  }
}

async function scanCode(
  code: string,
  packageJson?: string,
  aiExplain?: boolean,
): Promise<{ findings: Finding[]; summary: ScanSummary }> {
  const res = await fetch('http://localhost:3001/scan', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ code, filename: 'editor.ts', packageJson: packageJson || undefined, aiExplain: aiExplain || false }),
  })
  if (!res.ok) {
    const data = await res.json().catch(() => ({}))
    throw new Error((data as { error?: string }).error ?? `HTTP ${res.status}`)
  }
  return res.json()
}

// ── Export helpers ────────────────────────────────────────────────────────────

function downloadBlob(content: string, filename: string, mime: string) {
  const blob = new Blob([content], { type: mime })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  a.click()
  URL.revokeObjectURL(url)
}

function exportJSON(findings: Finding[], summary: ScanSummary) {
  downloadBlob(JSON.stringify({ findings, summary }, null, 2), 'scan-results.json', 'application/json')
}

function exportSARIF(findings: Finding[]) {
  const rules = Array.from(new Set(findings.map((f) => f.type))).map((id) => ({
    id,
    name: id,
    shortDescription: { text: id },
  }))

  const results = findings.map((f) => ({
    ruleId: f.type,
    level:
      f.severity === 'critical' || f.severity === 'high' ? 'error' :
      f.severity === 'medium' ? 'warning' : 'note',
    message: { text: f.message },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri: f.file ?? 'editor.ts' },
          region: { startLine: f.line, startColumn: f.column },
        },
      },
    ],
  }))

  const sarif = {
    version: '2.1.0',
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    runs: [{ tool: { driver: { name: 'ai-code-security-scanner', version: '0.1.0', rules } }, results }],
  }

  downloadBlob(JSON.stringify(sarif, null, 2), 'scan-results.sarif', 'application/json')
}

// ─────────────────────────────────────────────────────────────────────────────

async function scanRepo(
  repoUrl: string,
  branch: string,
): Promise<{ findings: Finding[]; summary: ScanSummary; filesScanned?: number }> {
  const res = await fetch('http://localhost:3001/scan-repo', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ repoUrl, branch: branch || 'main' }),
  })
  if (!res.ok) {
    const data = await res.json().catch(() => ({}))
    throw new Error((data as { error?: string }).error ?? `HTTP ${res.status}`)
  }
  return res.json()
}

function App() {
  const [status, setStatus] = useState<ScanStatus>('idle')
  const [findings, setFindings] = useState<Finding[]>([])
  const [summary, setSummary] = useState<ScanSummary | null>(null)
  const [errorMsg, setErrorMsg] = useState<string>('')
  const [code, setCode] = useState<string>('')
  const [packageJson, setPackageJson] = useState<string>('')
  const [showPkgJson, setShowPkgJson] = useState(false)
  const [activeTab, setActiveTab] = useState<EditorTab>('editor')
  const [repoUrl, setRepoUrl] = useState<string>('')
  const [repoBranch, setRepoBranch] = useState<string>('main')
  const [filesScanned, setFilesScanned] = useState<number | null>(null)
  const [aiExplain, setAiExplain] = useState<boolean>(false)
  const [history, setHistory] = useState<ScanHistoryEntry[]>(() => loadHistory())
  const [showHistory, setShowHistory] = useState<boolean>(false)
  const editorRef = useRef<CodeEditorHandle>(null)

  // Persist history whenever it changes
  useEffect(() => {
    saveHistory(history)
  }, [history])

  const addToHistory = useCallback((entry: ScanHistoryEntry) => {
    setHistory((prev) => [entry, ...prev].slice(0, HISTORY_MAX))
  }, [])

  const restoreFromHistory = useCallback((entry: ScanHistoryEntry) => {
    setFindings(entry.findings)
    setSummary(entry.summary)
    setStatus('success')
    setErrorMsg('')
    setFilesScanned(null)
    if (entry.code !== undefined) {
      setCode(entry.code)
      setActiveTab('editor')
    }
  }, [])

  const clearHistory = useCallback(() => {
    localStorage.removeItem(HISTORY_KEY)
    setHistory([])
    setShowHistory(false)
  }, [])

  const handleScan = async () => {
    setStatus('loading')
    setErrorMsg('')
    setFilesScanned(null)
    try {
      if (activeTab === 'repo') {
        const data = await scanRepo(repoUrl, repoBranch)
        setFindings(data.findings)
        setSummary(data.summary)
        setFilesScanned(data.filesScanned ?? null)
        addToHistory({
          id: `${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
          timestamp: new Date().toISOString(),
          source: repoUrl.trim() || 'github-repo',
          summary: data.summary,
          findings: data.findings,
        })
      } else {
        const data = await scanCode(code, packageJson || undefined, aiExplain)
        setFindings(data.findings)
        setSummary(data.summary)
        addToHistory({
          id: `${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
          timestamp: new Date().toISOString(),
          source: 'editor.ts',
          summary: data.summary,
          findings: data.findings,
          code,
        })
      }
      setStatus('success')
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err)
      if (msg.includes('fetch') || msg.toLowerCase().includes('failed to fetch') || msg.includes('ECONNREFUSED')) {
        setErrorMsg("Start the server with npm run dev:server")
      } else {
        setErrorMsg(msg)
      }
      setStatus('error')
    }
  }

  return (
    <div className="min-h-screen bg-[#0a0a0f] text-[#e6edf3] flex flex-col">
      {/* Header */}
      <header className="border-b border-[#1e1e2e] px-6 py-4 flex items-center gap-3 shrink-0">
        <svg
          width="22"
          height="22"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="2"
          strokeLinecap="round"
          strokeLinejoin="round"
          className="text-violet-400"
          aria-hidden="true"
        >
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
        </svg>
        <h1 className="text-base font-semibold tracking-tight">AI Code Security Scanner</h1>
        <span className="px-2 py-0.5 text-xs rounded-full border border-violet-500/40 text-violet-400 font-mono">
          MVP
        </span>

        {/* AI Explain toggle */}
        <label className="ml-auto flex items-center gap-2 cursor-pointer select-none" title="Request AI explanations and fix suggestions for each finding (requires ANTHROPIC_API_KEY)">
          <span className="text-xs text-[#7d8590] font-mono">AI Explain</span>
          <div
            onClick={() => setAiExplain((v) => !v)}
            className={`relative w-9 h-5 rounded-full border transition-colors cursor-pointer ${
              aiExplain ? 'bg-violet-500/30 border-violet-500/60' : 'bg-[#1e1e2e] border-[#30363d]'
            }`}
          >
            <span
              className={`absolute top-0.5 left-0.5 w-4 h-4 rounded-full transition-all ${
                aiExplain ? 'translate-x-4 bg-violet-400' : 'bg-[#7d8590]'
              }`}
            />
          </div>
        </label>
      </header>

      {/* Main split layout */}
      <main className="flex flex-1 overflow-hidden">
        {/* Left panel — 60% */}
        <section className="w-[60%] flex flex-col border-r border-[#1e1e2e] p-5 gap-3 overflow-y-auto">
          {/* Tab switcher */}
          <div className="flex items-center gap-1 border-b border-[#1e1e2e] pb-3 -mx-5 px-5">
            {(() => {
              const hasScanResults = status === 'success' && findings.length > 0
              const tabTop = hasScanResults ? topSeverity(findings) : null
              return (
                <>
                  <button
                    type="button"
                    onClick={() => setActiveTab('editor')}
                    className={`px-3 py-1.5 text-xs font-mono rounded-t transition-colors flex items-center gap-1.5 ${
                      activeTab === 'editor'
                        ? 'bg-violet-600/20 text-violet-400 border border-violet-500/40'
                        : 'text-[#7d8590] hover:text-[#e6edf3] border border-transparent'
                    }`}
                  >
                    Editor
                    {activeTab === 'editor' && tabTop && (
                      <span className={`px-1.5 py-0.5 text-[10px] font-semibold rounded border ${severityBadgeClass[tabTop]}`}>
                        {findings.length}
                      </span>
                    )}
                  </button>
                  <button
                    type="button"
                    onClick={() => setActiveTab('repo')}
                    className={`px-3 py-1.5 text-xs font-mono rounded-t transition-colors flex items-center gap-1.5 ${
                      activeTab === 'repo'
                        ? 'bg-violet-600/20 text-violet-400 border border-violet-500/40'
                        : 'text-[#7d8590] hover:text-[#e6edf3] border border-transparent'
                    }`}
                  >
                    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true">
                      <path d="M9 19c-5 1.5-5-2.5-7-3m14 6v-3.87a3.37 3.37 0 0 0-.94-2.61c3.14-.35 6.44-1.54 6.44-7A5.44 5.44 0 0 0 20 4.77 5.07 5.07 0 0 0 19.91 1S18.73.65 16 2.48a13.38 13.38 0 0 0-7 0C6.27.65 5.09 1 5.09 1A5.07 5.07 0 0 0 5 4.77a5.44 5.44 0 0 0-1.5 3.78c0 5.42 3.3 6.61 6.44 7A3.37 3.37 0 0 0 9 18.13V22"/>
                    </svg>
                    GitHub Repo
                    {activeTab === 'repo' && tabTop && (
                      <span className={`px-1.5 py-0.5 text-[10px] font-semibold rounded border ${severityBadgeClass[tabTop]}`}>
                        {findings.length}
                      </span>
                    )}
                  </button>
                </>
              )
            })()}
          </div>

          {activeTab === 'editor' ? (
            <>
              <div className="flex items-center justify-between">
                <span className="text-xs text-[#7d8590] uppercase tracking-widest font-mono">Editor</span>
                <span className="text-xs text-[#7d8590] font-mono">TypeScript / JavaScript</span>
              </div>
              <CodeEditor
                ref={editorRef}
                value={code}
                onChange={setCode}
                onScan={handleScan}
                isLoading={status === 'loading'}
              />

              {/* package.json section */}
              <div className="mt-1">
                <button
                  type="button"
                  onClick={() => setShowPkgJson((v) => !v)}
                  className="flex items-center gap-1.5 text-xs text-[#7d8590] hover:text-[#e6edf3] transition-colors font-mono"
                >
                  <svg
                    width="10"
                    height="10"
                    viewBox="0 0 24 24"
                    fill="none"
                    stroke="currentColor"
                    strokeWidth="2"
                    className={`transition-transform ${showPkgJson ? 'rotate-90' : ''}`}
                    aria-hidden="true"
                  >
                    <polyline points="9 18 15 12 9 6" />
                  </svg>
                  {showPkgJson ? 'Hide' : 'Add'} package.json{' '}
                  <span className="opacity-50">(scan for vulnerable deps)</span>
                </button>

                {showPkgJson && (
                  <div className="mt-2 flex flex-col gap-1">
                    <textarea
                      className="w-full bg-[#0d1117] text-[#e6edf3] font-mono rounded-lg p-3 resize-none border border-[#1e1e2e] focus:outline-none focus:border-violet-500/50 transition-colors leading-relaxed"
                      style={{
                        height: '120px',
                        fontSize: '12px',
                        fontFamily: '"JetBrains Mono", "Fira Code", monospace',
                      }}
                      placeholder={'{\n  "dependencies": {\n    "lodash": "4.17.10"\n  }\n}'}
                      value={packageJson}
                      onChange={(e) => setPackageJson(e.target.value)}
                      spellCheck={false}
                      autoCorrect="off"
                    />
                    <p className="text-xs text-[#7d8590] font-mono">
                      Paste your package.json to detect vulnerable or unpinned dependencies
                    </p>
                  </div>
                )}
              </div>
            </>
          ) : (
            <div className="flex flex-col gap-4 flex-1">
              <div className="flex items-center justify-between">
                <span className="text-xs text-[#7d8590] uppercase tracking-widest font-mono">GitHub Repository</span>
              </div>

              <div className="flex flex-col gap-3">
                <div className="flex flex-col gap-1">
                  <label className="text-xs text-[#7d8590] font-mono">Repository URL</label>
                  <input
                    type="text"
                    className="bg-[#0d1117] text-[#e6edf3] font-mono rounded-lg px-3 py-2.5 border border-[#1e1e2e] focus:outline-none focus:border-violet-500/50 transition-colors text-sm"
                    placeholder="https://github.com/owner/repo"
                    value={repoUrl}
                    onChange={(e) => setRepoUrl(e.target.value)}
                    spellCheck={false}
                  />
                </div>

                <div className="flex flex-col gap-1">
                  <label className="text-xs text-[#7d8590] font-mono">Branch</label>
                  <input
                    type="text"
                    className="bg-[#0d1117] text-[#e6edf3] font-mono rounded-lg px-3 py-2.5 border border-[#1e1e2e] focus:outline-none focus:border-violet-500/50 transition-colors text-sm"
                    placeholder="main"
                    value={repoBranch}
                    onChange={(e) => setRepoBranch(e.target.value)}
                    spellCheck={false}
                  />
                </div>

                <p className="text-xs text-[#7d8590] font-mono leading-relaxed">
                  Scans up to 50 .ts/.tsx/.js/.jsx files (max 200KB each) via GitHub Contents API.
                  Set <code className="bg-[#0d1117] px-1 rounded">GITHUB_TOKEN</code> env var to avoid rate limits.
                </p>

                <button
                  onClick={handleScan}
                  disabled={status === 'loading' || !repoUrl.trim()}
                  className="flex items-center justify-center gap-2 px-6 py-3 rounded-lg bg-violet-600 hover:bg-violet-500 disabled:opacity-50 disabled:cursor-not-allowed transition-all duration-150 font-medium text-sm text-white shadow-lg shadow-violet-900/30"
                >
                  {status === 'loading' ? (
                    <>
                      <svg className="animate-spin h-4 w-4 text-white" viewBox="0 0 24 24" fill="none" aria-hidden="true">
                        <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                        <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                      </svg>
                      Scanning Repo…
                    </>
                  ) : (
                    <>
                      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                      </svg>
                      Scan Repo
                    </>
                  )}
                </button>
              </div>
            </div>
          )}
        </section>

        {/* Results panel — 40% */}
        <section className="w-[40%] flex flex-col p-5 gap-4 overflow-y-auto">
          <div className="flex items-center justify-between gap-2">
            <span className="text-xs text-[#7d8590] uppercase tracking-widest font-mono">Results</span>
            <div className="flex items-center gap-1.5">
              {filesScanned !== null && status === 'success' && (
                <span className="text-xs text-[#7d8590] font-mono mr-2">{filesScanned} files scanned</span>
              )}
              {status === 'success' && findings.length > 0 && summary && (
                <>
                  <button
                    type="button"
                    onClick={() => exportJSON(findings, summary)}
                    className="flex items-center gap-1 px-2 py-0.5 text-xs font-mono rounded border border-[#30363d] text-[#7d8590] hover:border-violet-500/60 hover:text-violet-400 transition-colors"
                  >
                    <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true">
                      <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/>
                    </svg>
                    JSON
                  </button>
                  <button
                    type="button"
                    onClick={() => exportSARIF(findings)}
                    title="Download findings as SARIF 2.1.0 (compatible with GitHub Code Scanning and other SAST tools)"
                    className="flex items-center gap-1 px-2 py-0.5 text-xs font-mono rounded border border-[#30363d] text-[#7d8590] hover:border-violet-500/60 hover:text-violet-400 transition-colors"
                  >
                    <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true">
                      <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/>
                    </svg>
                    Download SARIF
                  </button>
                </>
              )}
            </div>
          </div>

          {/* Recent Scans panel */}
          {history.length > 0 && (
            <div className="border border-[#1e1e2e] rounded-lg overflow-hidden">
              <div className="w-full flex items-center justify-between px-3 py-2">
                <button
                  type="button"
                  onClick={() => setShowHistory((v) => !v)}
                  className="flex items-center gap-1.5 text-xs font-mono text-[#7d8590] hover:text-[#e6edf3] transition-colors"
                >
                  <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true">
                    <circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/>
                  </svg>
                  Recent Scans
                  <span className="px-1.5 py-0.5 rounded bg-[#0d1117] border border-[#30363d] text-[#7d8590]">{history.length}</span>
                  <svg
                    width="10"
                    height="10"
                    viewBox="0 0 24 24"
                    fill="none"
                    stroke="currentColor"
                    strokeWidth="2"
                    className={`transition-transform ${showHistory ? 'rotate-180' : ''}`}
                    aria-hidden="true"
                  >
                    <polyline points="6 9 12 15 18 9" />
                  </svg>
                </button>
                <button
                  type="button"
                  onClick={clearHistory}
                  title="Clear scan history"
                  className="flex items-center gap-1 px-2 py-0.5 text-xs font-mono rounded border border-[#30363d] text-[#7d8590] hover:border-red-500/40 hover:text-red-400 transition-colors"
                >
                  <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true">
                    <polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 01-2 2H8a2 2 0 01-2-2L5 6"/><path d="M10 11v6"/><path d="M14 11v6"/><path d="M9 6V4h6v2"/>
                  </svg>
                  Clear
                </button>
              </div>
              {showHistory && (
                <div className="border-t border-[#1e1e2e] divide-y divide-[#1e1e2e]">
                  {history.map((entry) => {
                    const sev = topSeverity(entry.findings)
                    const time = new Date(entry.timestamp)
                    const timeStr = time.toLocaleDateString(undefined, { month: 'short', day: 'numeric' })
                      + ' ' + time.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' })
                    return (
                      <button
                        key={entry.id}
                        type="button"
                        onClick={() => restoreFromHistory(entry)}
                        className="w-full flex items-center gap-2 px-3 py-2 hover:bg-[#0d1117] transition-colors text-left group"
                      >
                        <div className="flex-1 min-w-0">
                          <div className="text-xs font-mono text-[#e6edf3] truncate group-hover:text-violet-400 transition-colors">
                            {entry.source}
                          </div>
                          <div className="text-[10px] text-[#4a5668] font-mono mt-0.5">{timeStr}</div>
                        </div>
                        <div className="flex items-center gap-1.5 shrink-0">
                          {(['critical', 'high', 'medium', 'low'] as Severity[]).map((s) => {
                            const count = entry.findings.filter((f) => f.severity === s).length
                            if (!count) return null
                            return (
                              <span key={s} className={`px-1.5 py-0.5 text-[10px] font-semibold rounded border ${severityBadgeClass[s]}`}>
                                {count}
                              </span>
                            )
                          })}
                          {entry.findings.length === 0 && (
                            <span className="text-[10px] text-[#4a5668] font-mono">clean</span>
                          )}
                          {sev && (
                            <span className={`text-[10px] font-semibold uppercase tracking-wide ${
                              sev === 'critical' ? 'text-red-400' :
                              sev === 'high' ? 'text-orange-400' :
                              sev === 'medium' ? 'text-yellow-400' : 'text-gray-400'
                            }`}>{sev}</span>
                          )}
                        </div>
                      </button>
                    )
                  })}
                </div>
              )}
            </div>
          )}

          {status === 'idle' && history.length === 0 && (
            <div className="flex-1 flex items-center justify-center">
              <div className="text-center text-[#7d8590]">
                <svg
                  width="48"
                  height="48"
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="1"
                  className="mx-auto mb-3 opacity-30"
                  aria-hidden="true"
                >
                  <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                </svg>
                <p className="text-sm">Paste code and click Scan</p>
              </div>
            </div>
          )}

          {status === 'error' && (
            <div className="rounded-lg border border-red-500/30 bg-red-500/10 p-4 text-sm text-red-400 flex items-start gap-2">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="shrink-0 mt-0.5" aria-hidden="true">
                <circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>
              </svg>
              {errorMsg}
            </div>
          )}

          {(status === 'success') && summary && (
            <>
              <SummaryCards summary={summary} />
              <ScanResults
                findings={findings}
                onGoToLine={(line) => {
                  if (activeTab === 'editor') editorRef.current?.scrollToLine(line)
                }}
              />
            </>
          )}

          {status === 'loading' && (
            <div className="flex-1 flex items-center justify-center">
              <svg className="animate-spin h-8 w-8 text-violet-400" viewBox="0 0 24 24" fill="none" aria-label="Scanning…">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"/>
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"/>
              </svg>
            </div>
          )}
        </section>
      </main>
    </div>
  )
}

export default App
