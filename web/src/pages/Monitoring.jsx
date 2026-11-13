import { useMemo, useState } from 'react'
import { Activity, Siren, ShieldAlert, Globe2, Smartphone, ChevronDown, Search } from 'lucide-react'
import { api, ago, fmtDate } from '../api.js'
import { useLoad, PageHeader, Card, Badge, Button, ErrorBox, Loading, Seg, toast, Stat, Modal, Field, openModal, closeModal, usePreline, levelTone, Empty } from '../ui.jsx'
import { CodeBlock } from '../components.jsx'

const resultTone = { success: 'ok', failure: 'bad', locked: 'bad', blocked: 'warn', 'mfa-denied': 'warn' }
const statusTone = { open: 'bad', investigating: 'warn', 'closed-true-positive': 'ok', 'closed-false-positive': 'neutral' }
const ACTIONS = { 'block-ip': 'Block the source IP (adds it to CA006)', 'revoke-sessions': 'Revoke all sessions for the user', 'reset-mfa': 'Reset MFA (force re-registration)', 'disable-user': 'Disable the account' }

function Timeline({ buckets }) {
  const max = Math.max(1, ...buckets.map((b) => b.success + b.failure + b.blocked + b.mfaDenied))
  const W = 700, H = 150, bw = W / buckets.length
  const seg = [['success', '#34d399'], ['mfaDenied', '#fbbf24'], ['blocked', '#fb923c'], ['failure', '#fb7185']]
  return (
    <div>
      <svg viewBox={`0 0 ${W} ${H + 18}`} className="w-full" role="img" aria-label="Sign-ins per 6 hours over 7 days">
        {[0.25, 0.5, 0.75, 1].map((f) => <line key={f} x1="0" x2={W} y1={H - f * H} y2={H - f * H} stroke="rgba(255,255,255,.05)" />)}
        {buckets.map((b, i) => {
          let y = H
          return (
            <g key={i}>
              <title>{`${new Date(b.start).toLocaleString()}: ${b.success} ok, ${b.failure} failed, ${b.mfaDenied} MFA denied, ${b.blocked} blocked`}</title>
              {seg.map(([k, c]) => {
                const h = (b[k] / max) * (H - 6)
                y -= h
                return h > 0 ? <rect key={k} x={i * bw + 2} y={y} width={bw - 4} height={h} rx={2} fill={c} opacity={0.85} /> : null
              })}
              {i % 4 === 0 && <text x={i * bw + 2} y={H + 14} className="fill-zinc-500 text-[10px]">{new Date(b.start).toLocaleDateString(undefined, { weekday: 'short' })}</text>}
            </g>
          )
        })}
      </svg>
      <div className="mt-2 flex flex-wrap gap-3 text-[11px] text-zinc-400">
        {[['Success', '#34d399'], ['MFA denied', '#fbbf24'], ['Blocked by CA', '#fb923c'], ['Failed / locked', '#fb7185']].map(([l, c]) => <span key={l} className="flex items-center gap-1.5"><span className="size-2.5 rounded-sm" style={{ background: c }} />{l}</span>)}
      </div>
    </div>
  )
}

export default function Monitoring() {
  const [data, reload, error] = useLoad({ m: api.monitoring }, [], { poll: 20000 })
  const [open, setOpen] = useState(null)
  const [filter, setFilter] = useState('all')
  const [q, setQ] = useState('')
  const [tri, setTri] = useState(null)
  const [form, setForm] = useState({ status: 'closed-true-positive', notes: '', actions: [] })
  usePreline([data, open])

  const byId = useMemo(() => Object.fromEntries((data?.m.signIns || []).map((s) => [s.id, s])), [data])

  function triage(a) {
    setTri(a)
    setForm({ status: 'closed-true-positive', notes: '', actions: a.response.filter((r) => ACTIONS[r]).slice(0, 1) })
    openModal('triage')
  }
  async function submit() {
    try { await api.triage(tri.id, form); closeModal('triage'); await reload(); toast('Alert updated and response actions applied') } catch (e) { toast(e.message, 'err') }
  }

  if (!data) return <><ErrorBox error={error} /><Loading /></>
  const { m } = data
  const openAlerts = m.alerts.filter((a) => a.status === 'open')
  const log = m.signIns.filter((s) => (filter === 'all' || (filter === 'failed' ? s.result !== 'success' : s.source === 'live')) && (!q || `${s.username} ${s.ip} ${s.city} ${s.app}`.toLowerCase().includes(q.toLowerCase())))

  return (
    <div className="space-y-6">
      <PageHeader icon={Activity} eyebrow="Project 8 · identity threat detection · MITRE ATT&CK, NIST SI-4, IR-4" title="Identity threat detection"
        desc="A week of sign-in logs with six classic identity attacks hidden in normal traffic, plus every live sign-in to the built-in IdP. Seven detection rules run over the log like scheduled analytics rules in Microsoft Sentinel. Each alert carries its evidence, the ATT&CK technique and the KQL you would hunt with. Triage closes the loop: block the IP in Conditional Access, revoke sessions, reset MFA." />
      <ErrorBox error={error} />

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-5">
        <Stat label="Sign-ins (7 days)" value={m.stats.total} icon={Activity} />
        <Stat label="Failed, blocked or denied" value={m.stats.failed} icon={ShieldAlert} tone="warn" delay={60} />
        <Stat label="Successful with MFA" value={m.stats.mfaPercent} suffix="%" icon={Smartphone} tone={m.stats.mfaPercent > 90 ? 'ok' : 'warn'} delay={120} />
        <Stat label="Countries" value={m.stats.countries} icon={Globe2} tone="info" delay={180} />
        <Stat label="Open alerts" value={openAlerts.length} icon={Siren} tone={openAlerts.length ? 'bad' : 'ok'} delay={240} />
      </div>

      <Card title="Sign-in activity" subtitle="6-hour buckets, last 7 days. The spikes are the attacks.">
        <Timeline buckets={m.timeline} />
      </Card>

      <Card title="Alerts" subtitle="Open first, then by severity" pad={false}>
        {m.alerts.length === 0 ? <Empty icon={Siren}>No alerts.</Empty> : (
          <ul className="divide-y divide-white/[0.06]">
            {m.alerts.map((a, i) => (
              <li key={a.id} className="animate-fade-up" style={{ animationDelay: `${i * 30}ms` }}>
                <button type="button" onClick={() => setOpen(open === a.id ? null : a.id)} className="flex w-full flex-wrap items-center gap-3 px-5 py-3.5 text-start hover:bg-white/[0.02]">
                  <Badge tone={levelTone[a.severity]}>{a.severity}</Badge>
                  <div className="min-w-0 flex-1">
                    <div className="font-medium text-zinc-100">{a.title} <span className="font-mono text-xs text-zinc-500">{a.rule}</span></div>
                    <div className="truncate text-xs text-zinc-400">{a.summary}</div>
                  </div>
                  <Badge tone="violet">{a.technique.split(' ')[0]}</Badge>
                  <Badge tone={statusTone[a.status]}>{a.status.replace('closed-', 'closed: ').replace(/-/g, ' ')}</Badge>
                  <span className="text-xs text-zinc-500">{ago(a.lastSeen)}</span>
                  <ChevronDown className={`size-4 text-zinc-500 transition ${open === a.id ? 'rotate-180' : ''}`} />
                </button>
                {open === a.id && (
                  <div className="grid gap-4 px-5 pb-5 lg:grid-cols-2 animate-fade-in">
                    <div className="space-y-3">
                      <p className="text-sm text-zinc-300">{a.summary}</p>
                      <div className="flex flex-wrap gap-2 text-xs"><Badge tone="violet">{a.technique}</Badge><Badge>{a.tactic}</Badge>{a.user && <Badge tone="info">user {a.user}</Badge>}{a.ip && <Badge tone="warn">ip {a.ip}</Badge>}</div>
                      <div className="overflow-x-auto rounded-xl border border-white/[0.07]">
                        <table className="min-w-full text-xs">
                          <thead><tr><th className="th">Time</th><th className="th">User</th><th className="th">From</th><th className="th">Result</th></tr></thead>
                          <tbody>{a.evidence.slice(0, 12).map((id) => byId[id] && (
                            <tr key={id} className="row"><td className="td text-zinc-400">{fmtDate(byId[id].at)}</td><td className="td text-zinc-200">{byId[id].username}</td><td className="td text-zinc-400">{byId[id].city} · {byId[id].ip}</td><td className="td"><Badge tone={resultTone[byId[id].result]}>{byId[id].result}</Badge></td></tr>
                          ))}</tbody>
                        </table>
                        {a.evidence.length > 12 && <div className="px-3 py-2 text-[11px] text-zinc-500">+{a.evidence.length - 12} more events</div>}
                      </div>
                      {a.notes && <div className="rounded-xl border border-white/[0.07] p-3 text-xs text-zinc-300"><b>Notes</b> ({a.triagedBy}): {a.notes}{a.actionsDone?.length > 0 && <div className="mt-1 text-emerald-300">Done: {a.actionsDone.join(' · ')}</div>}</div>}
                    </div>
                    <div className="space-y-3">
                      <CodeBlock lang="KQL · Microsoft Sentinel hunting query" maxH="max-h-56">{a.kql}</CodeBlock>
                      <div className="rounded-xl border border-white/[0.07] p-3 text-xs">
                        <div className="mb-1 font-semibold text-zinc-200">Recommended response</div>
                        <ul className="list-disc space-y-0.5 ps-4 text-zinc-400">{a.response.map((r) => <li key={r}>{ACTIONS[r] || r}</li>)}</ul>
                      </div>
                      <Button onClick={() => triage(a)}>Triage alert</Button>
                    </div>
                  </div>
                )}
              </li>
            ))}
          </ul>
        )}
      </Card>

      <Card title="Sign-in log" subtitle="Newest first. Live entries come from the hosted sign-in page." pad={false}
        actions={<><div className="relative"><Search className="absolute start-2.5 top-2.5 size-3.5 text-zinc-500" /><input className="input w-48 ps-8 text-xs" placeholder="user, IP, city, app" value={q} onChange={(e) => setQ(e.target.value)} /></div><Seg value={filter} onChange={setFilter} options={[{ value: 'all', label: 'All' }, { value: 'failed', label: 'Not success' }, { value: 'live', label: 'Live only' }]} /></>}>
        <div className="max-h-[480px] overflow-auto">
          <table className="min-w-full">
            <thead className="sticky top-0 bg-zinc-900"><tr><th className="th">Time</th><th className="th">User</th><th className="th">App</th><th className="th">Location · IP</th><th className="th">Client</th><th className="th">Result</th><th className="th">MFA</th><th className="th">Risk</th></tr></thead>
            <tbody>
              {log.slice(0, 200).map((s) => (
                <tr key={s.id} className="row text-xs">
                  <td className="td whitespace-nowrap text-zinc-400">{fmtDate(s.at)}{s.source === 'live' && <Badge tone="violet" className="ms-1">live</Badge>}</td>
                  <td className="td text-zinc-200">{s.username}</td>
                  <td className="td text-zinc-400">{s.app}</td>
                  <td className="td whitespace-nowrap text-zinc-400">{s.city}, {s.country} · <span className="font-mono">{s.ip}</span></td>
                  <td className="td text-zinc-400">{s.client}</td>
                  <td className="td"><Badge tone={resultTone[s.result]}>{s.result}</Badge>{s.reason && <div className="mt-0.5 max-w-56 truncate text-[10px] text-zinc-500" title={s.reason}>{s.reason}</div>}</td>
                  <td className="td text-zinc-400">{s.mfa}</td>
                  <td className="td"><Badge tone={s.risk === 'high' ? 'bad' : s.risk === 'medium' ? 'warn' : 'ok'}>{s.risk}</Badge></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>

      <Modal id="triage" title={tri ? `Triage: ${tri.title}` : ''} size="md"
        footer={<><Button variant="ghost" data-hs-overlay="#triage">Cancel</Button><Button onClick={submit}>Save</Button></>}>
        {tri && <div className="space-y-4">
          <Field label="Status">
            <select className="input" value={form.status} onChange={(e) => setForm({ ...form, status: e.target.value })}>
              <option value="investigating">Investigating</option><option value="closed-true-positive">Closed: true positive</option><option value="closed-false-positive">Closed: false positive</option><option value="open">Re-open</option>
            </select>
          </Field>
          <Field label="Investigation notes" required={form.status.startsWith('closed')}>
            <textarea className="input" rows={3} value={form.notes} placeholder="e.g. Tor exit node, 12 accounts, no successful sign-ins. Blocked IP; confirmed lockout policy." onChange={(e) => setForm({ ...form, notes: e.target.value })} />
          </Field>
          <div>
            <div className="label">Response actions</div>
            <div className="space-y-1.5">
              {Object.entries(ACTIONS).filter(([k]) => (k !== 'block-ip' || tri.ip) && (k === 'block-ip' || tri.user)).map(([k, l]) => (
                <label key={k} className="flex items-center gap-2 text-sm text-zinc-300">
                  <input type="checkbox" className="size-4 rounded border-white/20 bg-zinc-900 text-violet-600" checked={form.actions.includes(k)} onChange={(e) => setForm({ ...form, actions: e.target.checked ? [...form.actions, k] : form.actions.filter((x) => x !== k) })} />
                  {l}{tri.response.includes(k) && <Badge tone="violet">recommended</Badge>}
                </label>
              ))}
            </div>
          </div>
        </div>}
      </Modal>
    </div>
  )
}
