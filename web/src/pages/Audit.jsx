import { useState } from 'react'
import { ScrollText, Download, RefreshCw } from 'lucide-react'
import { api, fmtDate } from '../api.js'
import { useLoad } from '../hooks.js'
import { PageHead, Badge, ErrorBox, Loading } from '../ui.jsx'

const kindFor = (a) =>
  a.includes('leaver') || a.includes('denied') ? 'bad'
    : a.includes('mover') || a.includes('role') ? 'warn'
      : a.includes('approved') || a.includes('joiner') ? 'ok' : 'neutral'

function toCSV(rows) {
  const esc = (v) => `"${String(v ?? '').replace(/"/g, '""')}"`
  const head = ['id', 'at', 'actor', 'action', 'target', 'detail']
  return [head.join(','), ...rows.map((r) => head.map((h) => esc(r[h])).join(','))].join('\n')
}

export default function Audit() {
  const [data, reload, error] = useLoad({ audit: api.audit })
  const [q, setQ] = useState('')
  const [action, setAction] = useState('')

  if (!data) return <><ErrorBox error={error} /><Loading /></>
  const actions = [...new Set(data.audit.map((a) => a.action))].sort()
  const needle = q.toLowerCase()
  const rows = data.audit.filter((a) =>
    (!action || a.action === action) &&
    (!needle || [a.actor, a.target, a.detail, a.action].some((v) => v?.toLowerCase().includes(needle))))

  function exportCSV() {
    const blob = new Blob([toCSV(rows)], { type: 'text/csv' })
    const url = URL.createObjectURL(blob)
    const link = Object.assign(document.createElement('a'), { href: url, download: `iam-audit-${new Date().toISOString().slice(0, 10)}.csv` })
    link.click()
    URL.revokeObjectURL(url)
  }

  return (
    <div>
      <PageHead icon={ScrollText} title="Audit log" job="Evidence for audits & access reviews">
        <button className="btn ghost" onClick={reload}><RefreshCw size={15} /> Refresh</button>
        <button className="btn primary" onClick={exportCSV}><Download size={15} /> Export CSV</button>
      </PageHead>
      <ErrorBox error={error} />
      <section className="panel">
        <div className="filters">
          <input placeholder="Search actor, target, detail…" value={q} onChange={(e) => setQ(e.target.value)} />
          <select value={action} onChange={(e) => setAction(e.target.value)}>
            <option value="">All actions</option>
            {actions.map((a) => <option key={a}>{a}</option>)}
          </select>
          <span className="muted small">{rows.length} of {data.audit.length} entries</span>
        </div>
        <div className="table-wrap">
          <table>
            <thead><tr><th>When</th><th>Actor</th><th>Action</th><th>Target</th><th>Detail</th></tr></thead>
            <tbody>
              {rows.map((a) => (
                <tr key={a.id}>
                  <td className="nowrap">{fmtDate(a.at)}</td>
                  <td>{a.actor}</td>
                  <td><Badge kind={kindFor(a.action)}>{a.action}</Badge></td>
                  <td className="mono">{a.target}</td>
                  <td>{a.detail}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  )
}
