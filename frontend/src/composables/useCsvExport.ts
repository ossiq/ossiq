import type { ReportRow } from '@/composables/useReportFilters'

const HEADERS = [
  { key: 'name', label: 'Dependency' },
  { key: 'cve', label: 'Security' },
  { key: 'drift', label: 'Drift Status' },
  { key: 'installed', label: 'Installed' },
  { key: 'latest', label: 'Latest' },
  { key: 'releases', label: 'Releases Distance' },
  { key: 'timeLag', label: 'Time Lag' },
] as const

function escapeCell(value: string): string {
  if (value.includes('"') || value.includes(',') || value.includes('\n')) {
    return `"${value.replace(/"/g, '""')}"`
  }
  return `"${value}"`
}

function rowToValues(row: ReportRow): string[] {
  return [
    row.pkg.package_name,
    String(row.cveCount),
    row.driftStatus,
    row.pkg.installed_version,
    row.pkg.latest_version ?? '',
    String(row.pkg.releases_lag ?? 0),
    String(row.pkg.time_lag_days ?? 0),
  ]
}

export function useCsvExport() {
  function exportCsv(rows: ReportRow[], filename = 'dependency_report.csv') {
    const headerLine = HEADERS.map((h) => escapeCell(h.label)).join(',')
    const dataLines = rows.map((row) =>
      rowToValues(row).map(escapeCell).join(','),
    )
    const csvContent = [headerLine, ...dataLines].join('\n')

    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' })
    const url = URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.setAttribute('href', url)
    link.setAttribute('download', filename)
    document.body.appendChild(link)
    link.click()
    document.body.removeChild(link)
    URL.revokeObjectURL(url)
  }

  return { exportCsv }
}
