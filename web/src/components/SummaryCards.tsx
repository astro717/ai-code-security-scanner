
export interface ScanSummary {
  critical: number
  high: number
  medium: number
  low: number
  total: number
}

interface SummaryCardsProps {
  summary: ScanSummary
}

const SEVERITY_CONFIG = [
  {
    key: 'critical' as const,
    label: 'Critical',
    color: '#ef4444',
    iconPath: 'M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5',
  },
  {
    key: 'high' as const,
    label: 'High',
    color: '#f97316',
    iconPath: 'M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0zM12 9v4M12 17h.01',
  },
  {
    key: 'medium' as const,
    label: 'Medium',
    color: '#eab308',
    iconPath: 'M12 22c5.523 0 10-4.477 10-10S17.523 2 12 2 2 6.477 2 12s4.477 10 10 10zM12 8v4M12 16h.01',
  },
  {
    key: 'low' as const,
    label: 'Low',
    color: '#6b7280',
    iconPath: 'M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z',
  },
]

export function SummaryCards({ summary }: SummaryCardsProps) {
  return (
    <div className="grid grid-cols-2 gap-2">
      {SEVERITY_CONFIG.map(({ key, label, color, iconPath }) => (
        <div
          key={key}
          className="rounded-lg border p-3 flex flex-col gap-1 transition-opacity duration-200"
          style={{
            borderColor: `${color}33`,
            backgroundColor: `${color}0d`,
          }}
        >
          <div className="flex items-center justify-between">
            <span
              className="text-2xl font-bold font-mono leading-none"
              style={{ color }}
            >
              {summary[key]}
            </span>
            <svg
              width="18"
              height="18"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
              style={{ color, opacity: 0.7 }}
              aria-hidden="true"
            >
              <path d={iconPath} />
            </svg>
          </div>
          <span className="text-xs text-[#7d8590]">{label}</span>
        </div>
      ))}
    </div>
  )
}
