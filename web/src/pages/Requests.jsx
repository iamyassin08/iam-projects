import { useMemo, useState } from 'react'
import { KeyRound, Check, X, AlertTriangle } from 'lucide-react'
import { api, fmtDate } from '../api.js'
import { useLoad, useToast } from '../hooks.js'
import { PageHead, Toast, Badge, ErrorBox, Loading, Field } from '../ui.jsx'

export default function Requests() {
  const [data, reload, error] = useLoad({ catalog: api.catalog, people: api.identities, requests: api.requests })
  const [toast, show] = useToast()
  const [filter, setFilter] = useState('pending')
  const [f, setF] = useState({ identityId: '', entitlementId: '', justification: '' })

  const look = useMemo(() => {
    if (!data) return {}
    const ent = Object.fromEntries(data.catalog.entitlements.map((e) => [e.id, e]))
    const sys = Object.fromEntries(data.catalog.systems.map((s) => [s.id, s]))
    const ppl = Object.fromEntries(data.people.map((p) => [p.id, p]))
    return { ent, sys, ppl }
  }, [data])

  if (!data) return <><ErrorBox error={error} /><Loading /></>

  const active = data.people.filter((p) => p.status === 'active')
  const shown = data.requests.filter((r) => filter === 'all' || r.status === filter)

  async function submit(e) {
    e.preventDefault()
    try {
      const r = await api.newRequest(f)
      await reload()
      setF({ ...f, justification: '' })
      show(r.sodConflict ? 'Request created — SoD conflict flagged' : 'Request submitted', r.sodConflict ? 'warn' : 'ok')
    } catch (err) { show(err.message, 'err') }
  }

  async function decide(r, approve) {
    let reason = ''
    if (approve && r.sodConflict) {
      reason = prompt(`SoD conflict:\n${r.sodConflict}\n\nDocument the risk acceptance (owner, compensating control, expiry):`) || ''
      if (!reason.trim()) return show('Approval cancelled — risk acceptance is required', 'warn')
    } else if (!approve) {
      reason = prompt('Reason for denial:') ?? null
      if (reason === null) return
    } else {
      reason = prompt('Approval note (optional):') || ''
    }
    try {
      await (approve ? api.approve(r.id, reason) : api.deny(r.id, reason))
      await reload()
      show(approve ? 'Approved and provisioned' : 'Request denied')
    } catch (err) { show(err.message, 'err') }
  }

  return (
    <div>
      <PageHead icon={KeyRound} title="Access requests" job="Request & approval governance · SoD" />
      <ErrorBox error={error} />

      <div className="grid-2 wide-right">
        <section className="panel">
          <h3>New request</h3>
          <form className="form" onSubmit={submit}>
            <Field label="Requested for">
              <select required value={f.identityId} onChange={(e) => setF({ ...f, identityId: e.target.value })}>
                <option value="">Choose…</option>
                {active.map((p) => <option key={p.id} value={p.id}>{p.name} · {p.department}</option>)}
              </select>
            </Field>
            <Field label="Entitlement">
              <select required value={f.entitlementId} onChange={(e) => setF({ ...f, entitlementId: e.target.value })}>
                <option value="">Choose…</option>
                {data.catalog.systems.map((s) => {
                  const ents = data.catalog.entitlements.filter((e) => e.systemId === s.id)
                  return ents.length ? (
                    <optgroup key={s.id} label={s.name}>
                      {ents.map((e) => <option key={e.id} value={e.id}>{e.name}{e.privileged ? ' ★ privileged' : ''}</option>)}
                    </optgroup>
                  ) : null
                })}
              </select>
            </Field>
            <Field label="Business justification">
              <textarea required rows={3} value={f.justification}
                onChange={(e) => setF({ ...f, justification: e.target.value })}
                placeholder="What do you need it for, and for how long?" />
            </Field>
            <button className="btn primary">Submit request</button>
          </form>
          <h3 className="mt">SoD rules</h3>
          <ul className="rules">
            {data.catalog.sodRules.map((r) => (
              <li key={r.id}><Badge kind="warn">{r.id}</Badge> {look.ent[r.a]?.name} + {look.ent[r.b]?.name}
                <div className="muted small">{r.description}</div></li>
            ))}
          </ul>
        </section>

        <section className="panel">
          <div className="row-between">
            <h3>Queue</h3>
            <div className="seg">
              {['pending', 'approved', 'denied', 'all'].map((k) => (
                <button key={k} className={filter === k ? 'active' : ''} onClick={() => setFilter(k)}>{k}</button>
              ))}
            </div>
          </div>
          {shown.length === 0 && <p className="muted">Nothing here.</p>}
          <div className="req-list">
            {shown.map((r) => {
              const e = look.ent[r.entitlementId]
              return (
                <article key={r.id} className={`req ${r.sodConflict ? 'flag' : ''}`}>
                  <div className="row-between">
                    <div>
                      <strong>{look.ppl[r.identityId]?.name || r.identityId}</strong> → {e?.name}
                      <span className="muted"> · {look.sys[e?.systemId]?.name}</span>
                      {e?.privileged && <Badge kind="bad">privileged</Badge>}
                    </div>
                    <Badge kind={r.status === 'approved' ? 'ok' : r.status === 'denied' ? 'bad' : 'neutral'}>{r.status}</Badge>
                  </div>
                  <p className="just">“{r.justification}”</p>
                  {r.sodConflict && <p className="sod"><AlertTriangle size={14} /> {r.sodConflict}</p>}
                  <div className="muted small">
                    {r.id} · requested {fmtDate(r.requestedAt)}
                    {r.decidedBy && <> · {r.status} by {r.decidedBy} {fmtDate(r.decidedAt)}</>}
                    {r.reason && <> · “{r.reason}”</>}
                  </div>
                  {r.status === 'pending' && (
                    <div className="req-actions">
                      <button className="btn small primary" onClick={() => decide(r, true)}><Check size={14} /> Approve</button>
                      <button className="btn small ghost" onClick={() => decide(r, false)}><X size={14} /> Deny</button>
                    </div>
                  )}
                </article>
              )
            })}
          </div>
        </section>
      </div>
      <Toast toast={toast} />
    </div>
  )
}
