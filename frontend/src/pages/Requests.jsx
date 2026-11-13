import { useMemo, useState } from 'react'
import { KeyRound, Check, X, AlertTriangle, Send } from 'lucide-react'
import { api, fmtDate, ago } from '../api.js'
import { makeLookups } from '../lookups.js'
import { useLoad, PageHeader, Card, Badge, Button, ErrorBox, Loading, Field, ask, toast, Avatar, Seg, Empty, usePreline } from '../ui.jsx'

export default function Requests() {
  const [data, reload, error] = useLoad({ catalog: api.catalog, people: api.identities, requests: api.requests })
  const [filter, setFilter] = useState('pending')
  const [f, setF] = useState({ identityId: '', entitlementId: '', justification: '' })
  const L = useMemo(() => makeLookups(data?.catalog, data?.people), [data])
  usePreline([data, filter])

  if (!data) return <><ErrorBox error={error} /><Loading /></>
  const active = data.people.filter((p) => p.status === 'active')
  const shown = data.requests.filter((r) => filter === 'all' || r.status === filter)
  const counts = data.requests.reduce((a, r) => ({ ...a, [r.status]: (a[r.status] || 0) + 1 }), {})

  async function submit(e) {
    e.preventDefault()
    try {
      const r = await api.newRequest(f)
      await reload()
      setF({ ...f, justification: '' })
      toast(r.sodConflict ? 'Request created; SoD conflict flagged for the approver' : 'Request submitted', r.sodConflict ? 'warn' : 'ok')
    } catch (err) { toast(err.message, 'err') }
  }

  async function decide(r, approve) {
    let reason
    if (approve && r.sodConflict) {
      reason = await ask({ title: 'Risk acceptance required', message: <>This request violates <span className="code">{r.sodConflict}</span>. Approving it is a documented exception: name the risk owner, the compensating control and an expiry.</>, label: 'Risk acceptance', placeholder: 'CFO accepts for 30 days; payments over $10k need second approval', required: true, confirm: 'Approve with exception', tone: 'danger' })
    } else if (approve) {
      reason = await ask({ title: 'Approve request', label: 'Approval note (optional)', confirm: 'Approve and provision' })
    } else {
      reason = await ask({ title: 'Deny request', label: 'Reason for denial', required: true, confirm: 'Deny', tone: 'danger' })
    }
    if (reason === null) return
    try {
      await (approve ? api.approve(r.id, reason) : api.deny(r.id, reason))
      await reload()
      toast(approve ? 'Approved and provisioned' : 'Request denied')
    } catch (err) { toast(err.message, 'err') }
  }

  return (
    <div className="space-y-6">
      <PageHeader icon={KeyRound} eyebrow="Request & approval governance · NIST AC-5" title="Access requests"
        desc="Access outside a role needs a business justification and an accountable approver. Segregation-of-duties conflicts are detected when the request is raised, and approving one requires a written risk acceptance that the controls lab checks for." />
      <ErrorBox error={error} />
      <div className="grid gap-6 lg:grid-cols-5">
        <div className="space-y-6 lg:col-span-2">
          <Card title="New request" delay={60}>
            <form className="grid gap-4" onSubmit={submit}>
              <Field label="Requested for" required>
                <select required className="input" value={f.identityId} onChange={(e) => setF({ ...f, identityId: e.target.value })}>
                  <option value="">Choose…</option>
                  {active.map((p) => <option key={p.id} value={p.id}>{p.name} · {p.department}</option>)}
                </select>
              </Field>
              <Field label="Entitlement" required>
                <select required className="input" value={f.entitlementId} onChange={(e) => setF({ ...f, entitlementId: e.target.value })}>
                  <option value="">Choose…</option>
                  {data.catalog.systems.map((s) => {
                    const ents = data.catalog.entitlements.filter((e) => e.systemId === s.id)
                    return ents.length ? <optgroup key={s.id} label={s.name}>{ents.map((e) => <option key={e.id} value={e.id}>{e.name}{e.privileged ? ' ★' : ''}</option>)}</optgroup> : null
                  })}
                </select>
              </Field>
              <Field label="Business justification" required>
                <textarea required rows={3} className="input" value={f.justification} onChange={(e) => setF({ ...f, justification: e.target.value })} placeholder="What for, and for how long?" />
              </Field>
              <div className="flex justify-end"><Button type="submit"><Send className="size-4" /> Submit</Button></div>
            </form>
          </Card>
          <Card title="Segregation-of-duties rules" subtitle="Toxic combinations nobody should hold together" delay={120}>
            <ul className="space-y-3">
              {data.catalog.sodRules.map((r) => (
                <li key={r.id} className="text-sm">
                  <div className="flex flex-wrap items-center gap-1.5"><Badge tone="warn">{r.id}</Badge><span className="text-zinc-200">{L.entName(r.a)}</span><span className="text-zinc-500">+</span><span className="text-zinc-200">{L.entName(r.b)}</span></div>
                  <div className="mt-1 text-xs text-zinc-500">{r.description}</div>
                </li>
              ))}
            </ul>
          </Card>
        </div>

        <Card className="lg:col-span-3" title="Approval queue" delay={90}
          actions={<Seg value={filter} onChange={setFilter} options={['pending', 'approved', 'denied', 'all'].map((k) => ({ value: k, label: `${k}${k !== 'all' && counts[k] ? ` · ${counts[k]}` : ''}` }))} />}>
          {shown.length === 0 && <Empty>Nothing in this queue.</Empty>}
          <div key={filter} className="space-y-3">
            {shown.map((r, i) => {
              const e = L.ent[r.entitlementId]
              return (
                <article key={r.id} className={`rounded-xl border p-4 transition-all hover:border-white/15 animate-fade-up ${r.sodConflict ? 'border-amber-500/30 bg-amber-500/[0.03]' : 'border-white/[0.07] bg-white/[0.02]'}`} style={{ animationDelay: `${i * 40}ms` }}>
                  <div className="flex flex-wrap items-start justify-between gap-3">
                    <div className="flex items-center gap-3">
                      <Avatar name={L.person(r.identityId)} />
                      <div>
                        <div className="text-sm text-zinc-100"><span className="font-semibold">{L.person(r.identityId)}</span> → {e?.name}</div>
                        <div className="text-xs text-zinc-500">{L.sysOf(r.entitlementId)} · {r.id} · {ago(r.requestedAt)}</div>
                      </div>
                    </div>
                    <div className="flex gap-1.5">{e?.privileged && <Badge tone="bad">privileged</Badge>}<Badge tone={r.status === 'approved' ? 'ok' : r.status === 'denied' ? 'bad' : 'neutral'} dot>{r.status}</Badge></div>
                  </div>
                  <p className="mt-3 text-sm italic text-zinc-400">“{r.justification}”</p>
                  {r.sodConflict && <p className="mt-2 flex items-center gap-1.5 text-xs font-medium text-amber-300"><AlertTriangle className="size-3.5" /> {r.sodConflict}</p>}
                  {r.decidedBy && <p className="mt-2 text-xs text-zinc-500">{r.status} by {r.decidedBy} · {fmtDate(r.decidedAt)}{r.reason && <> · “{r.reason}”</>}</p>}
                  {r.status === 'pending' && (
                    <div className="mt-3 flex gap-2">
                      <Button size="sm" variant="success" onClick={() => decide(r, true)}><Check className="size-3.5" /> Approve</Button>
                      <Button size="sm" variant="ghost" onClick={() => decide(r, false)}><X className="size-3.5" /> Deny</Button>
                    </div>
                  )}
                </article>
              )
            })}
          </div>
        </Card>
      </div>
    </div>
  )
}
