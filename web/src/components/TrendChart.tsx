/**
 * Severity trend sparkline chart — shows finding counts across recent scan history.
 * Uses inline SVG (no chart library dependency) to render stacked bars for
 * critical/high/medium/low findings per scan.
 */

import type { ScanSummary } from './SummaryCards'

interface HistoryEntry {
  id: string
  timestamp: string
  source: string
  summary: ScanSummary
}

interface TrendChartProps {
  history: HistoryEntry[]
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: '#ef4444',
  high:     '#f97316',
  medium:   '#eab308',
  low:      '#6b7280',
}

const BAR_WIDTH = 24
const BAR_GAP = 6
const CHART_HEIGHT = 80
const LABEL_HEIGHT = 16

export function TrendChart({ history }: TrendChartProps) {
  if (history.length < 2) return null

  // Show last 10 scans, oldest first (left to right)
  const entries = [...history].reverse().slice(-10)

  const maxTotal = Math.max(...entries.map((e) => e.summary.total), 1)

  const totalWidth = entries.length * (BAR_WIDTH + BAR_GAP) - BAR_GAP
  const totalHeight = CHART_HEIGHT + LABEL_HEIGHT + 8

  return (
    <div className="border border-[#1e1e2e] rounded-lg p-3">
      <div className="flex items-center justify-between mb-2">
        <span className="text-xs text-[#7d8590] font-mono uppercase tracking-widest">Severity Trend</span>
        <span className="text-[10px] text-[#4a5668] font-mono">Last {entries.length} scans</span>
      </div>
      <svg
        width="100%"
        viewBox={`0 0 ${totalWidth} ${totalHeight}`}
        className="overflow-visible"
        role="img"
        aria-label="Severity trend chart"
      >
        {/* Gridlines */}
        {[0, 0.25, 0.5, 0.75, 1].map((pct) => (
          <line
            key={pct}
            x1="0"
            y1={CHART_HEIGHT * (1 - pct)}
            x2={totalWidth}
            y2={CHART_HEIGHT * (1 - pct)}
            stroke="#1e1e2e"
            strokeWidth="0.5"
          />
        ))}

        {entries.map((entry, i) => {
          const x = i * (BAR_WIDTH + BAR_GAP)
          const { critical, high, medium, low } = entry.summary

          // Stacked bar: critical at bottom, then high, medium, low
          const segments = [
            { count: critical, color: SEVERITY_COLORS.critical },
            { count: high, color: SEVERITY_COLORS.high },
            { count: medium, color: SEVERITY_COLORS.medium },
            { count: low, color: SEVERITY_COLORS.low },
          ].filter((s) => s.count > 0)

          const totalBarHeight = (entry.summary.total / maxTotal) * CHART_HEIGHT
          let yOffset = CHART_HEIGHT - totalBarHeight

          const time = new Date(entry.timestamp)
          const label = time.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' })

          return (
            <g key={entry.id}>
              {/* Hover area */}
              <title>
                {entry.source} — {entry.summary.total} finding(s)
                {critical ? ` | ${critical} critical` : ''}
                {high ? ` | ${high} high` : ''}
                {medium ? ` | ${medium} medium` : ''}
                {low ? ` | ${low} low` : ''}
              </title>

              {/* Empty scan indicator */}
              {entry.summary.total === 0 && (
                <rect
                  x={x}
                  y={CHART_HEIGHT - 2}
                  width={BAR_WIDTH}
                  height={2}
                  rx={1}
                  fill="#22c55e"
                  opacity={0.4}
                />
              )}

              {/* Stacked segments */}
              {segments.map((seg, si) => {
                const segHeight = (seg.count / maxTotal) * CHART_HEIGHT
                const rect = (
                  <rect
                    key={si}
                    x={x}
                    y={yOffset}
                    width={BAR_WIDTH}
                    height={segHeight}
                    rx={si === 0 ? 3 : 0}
                    fill={seg.color}
                    opacity={0.7}
                  />
                )
                yOffset += segHeight
                return rect
              })}

              {/* Time label */}
              <text
                x={x + BAR_WIDTH / 2}
                y={CHART_HEIGHT + LABEL_HEIGHT + 2}
                textAnchor="middle"
                fill="#4a5668"
                fontSize="7"
                fontFamily="'JetBrains Mono', monospace"
              >
                {label}
              </text>
            </g>
          )
        })}
      </svg>
    </div>
  )
}
