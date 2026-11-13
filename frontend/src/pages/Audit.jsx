import { useState } from 'react'
import { ScrollText, Download, RefreshCw, Search } from 'lucide-react'
import { api, fmtDate, downloadFile, toCSV } from '../api.js'
import { useLoad, PageHeader, Card, Badge, Button, ErrorBox, Loading, Empty } from '../ui.jsx'

const tone = (a) =>
  /leaver|denied|revoke|disable|breakglass|expired/.test(a) ? 'bad'
    : /mover|role|adopt|owner|eligibility/.test(a) ? 'warn'
      : /approved|joiner|keep|rehire|reviewed|launched|closed/.test(a) ? 'ok'
        : /scim|pam|token/.test(a) ? 'info' : 'neutral'

export default function Audit() {
  const [data, reload, error] = useLoad({ audit: api.audit })
  const [q, setQ] = useState('')
  const [domain, setDomain] = useState('')
  if (!data) return <><ErrorBox error={error} /><Loading /></>

  const domains = [...new Set(data.audit.map((a) => a.action.split('.')[0]))].sort()
  const needle = q.toLowerCase()
  const rows = data.audit.filter((a) => (!domain || a.action.startsWith(domain + '.')) &&
    (!needle || [a.actor, a.target, a.detail, a.action].some((v) => v?.toLowerCase().includes(needle))))

  return (
    <div className="space-y-6">
      <PageHeader icon={ScrollText} eyebrow="Evidence · NIST AU-2, AU-3" title="Audit log"
        desc="Every grant, revoke, decision, elevation, SCIM call and remediation is recorded with who, what, when and why. SCIM changes are attributed to the token that made them (scim:<name>). Export the filtered view as CSV evidence.">
        <Button variant="ghost" onClick={reload}><RefreshCw className="size-4" /> Refresh</Button>
        <Button onClick={() => downloadFile(`iam-audit-${new Date().toISOString().slice(0, 10)}.csv`, toCSV(rows, ['id', 'at', 'actor', 'action', 'target', 'detail']), 'text/csv')}><Download className="size-4" /> Export CSV</Button>
      </PageHeader>
      <ErrorBox error={error} />
      <Card pad={false} delay={60}
        title={`${rows.length} of ${data.audit.length} events`}
        actions={<>
          <div className="relative"><Search className="pointer-events-none absolute start-2.5 top-2.5 size-4 text-zinc-500" /><input className="input w-60 ps-8" placeholder="Search actor, target, detail…" value={q} onChange={(e) => setQ(e.target.value)} /></div>
          <select className="input w-40" value={domain} onChange={(e) => setDomain(e.target.value)}><option value="">All domains</option>{domains.map((d) => <option key={d} value={d}>{d}</option>)}</select>
        </>}>
        {rows.length === 0 ? <Empty>No matching events.</Empty> : (
          <div className="overflow-x-auto">
            <table className="min-w-full">
              <thead><tr><th className="th ps-5">When</th><th className="th">Actor</th><th className="th">Action</th><th className="th">Target</th><th className="th pe-5">Detail</th></tr></thead>
              <tbody>
                {rows.map((a, i) => (
                  <tr key={a.id} className="row animate-fade-in" style={{ animationDelay: `${Math.min(i, 20) * 20}ms` }}>
                    <td className="td ps-5 whitespace-nowrap text-xs text-zinc-400">{fmtDate(a.at)}</td>
                    <td className="td whitespace-nowrap"><span className={a.actor.startsWith('scim:') ? 'code' : a.actor.startsWith('system') ? 'text-zinc-500' : 'text-zinc-200'}>{a.actor}</span></td>
                    <td className="td"><Badge tone={tone(a.action)}>{a.action}</Badge></td>
                    <td className="td"><span className="code">{a.target}</span></td>
                    <td className="td pe-5 text-zinc-300">{a.detail}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  )
}
