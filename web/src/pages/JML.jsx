import { useMemo, useState } from 'react'
import { Users, UserPlus, ArrowRightLeft, UserX } from 'lucide-react'
import { api, fmtDate } from '../api.js'
import { useLoad, useToast } from '../hooks.js'
import { PageHead, Toast, Badge, ErrorBox, Loading, Field } from '../ui.jsx'

const TABS = [
  { id: 'joiner', label: 'Joiner', icon: UserPlus },
  { id: 'mover', label: 'Mover', icon: ArrowRightLeft },
  { id: 'leaver', label: 'Leaver', icon: UserX },
]

export default function JML() {
  const [data, reload, error] = useLoad({ catalog: api.catalog, people: api.identities, events: api.jmlEvents })
  const [tab, setTab] = useState('joiner')
  const [selected, setSelected] = useState(null)
  const [access, setAccess] = useState([])
  const [toast, show] = useToast()

  const entName = useMemo(() => {
    const m = {}
    data?.catalog.entitlements.forEach((e) => (m[e.id] = e))
    return (id) => m[id]?.name || id
  }, [data])
  const roleName = (id) => data?.catalog.roles.find((r) => r.id === id)?.name || id
  const personName = (id) => data?.people.find((p) => p.id === id)?.name || id

  async function pick(p) {
    setSelected(p)
    try { setAccess(await api.access(p.id)) } catch (e) { show(e.message, 'err') }
  }

  async function run(fn, okMsg) {
    try {
      const res = await fn()
      await reload()
      if (selected) setAccess(await api.access(selected.id).catch(() => []))
      show(okMsg(res))
    } catch (e) { show(e.message, 'err') }
  }

  if (!data) return <><ErrorBox error={error} /><Loading /></>
  const active = data.people.filter((p) => p.status === 'active')

  return (
    <div>
      <PageHead icon={Users} title="JML workflow" job="Identity lifecycle · Joiner · Mover · Leaver" />
      <ErrorBox error={error} />

      <div className="grid-2">
        <section className="panel">
          <div className="tabs">
            {TABS.map(({ id, label, icon: Icon }) => (
              <button key={id} className={tab === id ? 'active' : ''} onClick={() => setTab(id)}>
                <Icon size={15} /> {label}
              </button>
            ))}
          </div>
          {tab === 'joiner' && <JoinerForm roles={data.catalog.roles} people={active}
            onSubmit={(b) => run(() => api.joiner(b), (r) => `${r.name} created with birthright access`)} />}
          {tab === 'mover' && <MoverForm roles={data.catalog.roles} people={active} roleName={roleName}
            onSubmit={(b) => run(() => api.mover(b), (r) => `Moved: +${r.granted.length} / −${r.revoked.length} entitlements`)} />}
          {tab === 'leaver' && <LeaverForm people={active}
            onSubmit={(b) => run(() => api.leaver(b), (r) => `Disabled; revoked ${r.revoked.length} entitlements`)} />}
        </section>

        <section className="panel">
          <h3>Lifecycle history</h3>
          <ul className="timeline">
            {data.events.slice(0, 12).map((ev) => (
              <li key={ev.id}>
                <Badge kind={ev.type === 'leaver' ? 'bad' : ev.type === 'mover' ? 'warn' : 'ok'}>{ev.type}</Badge>
                <div>
                  <div>{ev.summary}</div>
                  <div className="muted small">
                    {fmtDate(ev.at)}
                    {ev.granted.length > 0 && <> · <span className="plus">+{ev.granted.map(entName).join(', ')}</span></>}
                    {ev.revoked.length > 0 && <> · <span className="minus">−{ev.revoked.map(entName).join(', ')}</span></>}
                  </div>
                </div>
              </li>
            ))}
          </ul>
        </section>
      </div>

      <section className="panel">
        <h3>Directory</h3>
        <div className="table-wrap">
          <table>
            <thead><tr><th>Name</th><th>Title</th><th>Department</th><th>Role</th><th>Manager</th><th>Status</th><th>Grants</th></tr></thead>
            <tbody>
              {data.people.map((p) => (
                <tr key={p.id} className={`clickable ${selected?.id === p.id ? 'sel' : ''}`} onClick={() => pick(p)}>
                  <td><strong>{p.name}</strong><div className="muted small">{p.email}</div></td>
                  <td>{p.title}</td><td>{p.department}</td><td>{roleName(p.roleId)}</td><td>{p.manager}</td>
                  <td><Badge kind={p.status === 'active' ? 'ok' : 'bad'}>{p.status}</Badge></td>
                  <td>{p.grantCount}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      {selected && (
        <section className="panel">
          <h3>Current access · {personName(selected.id)}</h3>
          {access.length === 0 ? <p className="muted">No access.</p> : (
            <div className="chips">
              {access.map((g) => (
                <span key={g.entitlementId} className={`chip ${g.source}`}>
                  {entName(g.entitlementId)} <em>{g.source}</em>
                </span>
              ))}
            </div>
          )}
        </section>
      )}
      <Toast toast={toast} />
    </div>
  )
}

function JoinerForm({ roles, people, onSubmit }) {
  const [f, setF] = useState({ name: '', title: '', manager: '', roleId: roles[0]?.id || '', email: '', startDate: '' })
  const set = (k) => (e) => setF({ ...f, [k]: e.target.value })
  const role = roles.find((r) => r.id === f.roleId)
  return (
    <form className="form" onSubmit={(e) => { e.preventDefault(); onSubmit(f); setF({ ...f, name: '', title: '', email: '' }) }}>
      <Field label="Full name"><input required value={f.name} onChange={set('name')} placeholder="Jordan Reyes" /></Field>
      <Field label="Job title"><input value={f.title} onChange={set('title')} placeholder="Software Engineer I" /></Field>
      <Field label="Role">
        <select value={f.roleId} onChange={set('roleId')}>
          {roles.map((r) => <option key={r.id} value={r.id}>{r.name} — {r.department}</option>)}
        </select>
      </Field>
      <Field label="Manager">
        <select value={f.manager} onChange={set('manager')}>
          <option value="">—</option>
          {people.map((p) => <option key={p.id}>{p.name}</option>)}
        </select>
      </Field>
      <Field label="Email (optional)"><input value={f.email} onChange={set('email')} placeholder="auto: first.last@demo.local" /></Field>
      <Field label="Start date"><input type="date" value={f.startDate} onChange={set('startDate')} /></Field>
      {role && <p className="muted small">Birthright access: {role.entitlements.length} entitlements from {role.name}.</p>}
      <button className="btn primary">Onboard joiner</button>
    </form>
  )
}

function MoverForm({ roles, people, roleName, onSubmit }) {
  const [f, setF] = useState({ identityId: people[0]?.id || '', newRoleId: '', newTitle: '' })
  const set = (k) => (e) => setF({ ...f, [k]: e.target.value })
  const person = people.find((p) => p.id === f.identityId)
  return (
    <form className="form" onSubmit={(e) => { e.preventDefault(); onSubmit(f) }}>
      <Field label="Identity">
        <select value={f.identityId} onChange={set('identityId')}>
          {people.map((p) => <option key={p.id} value={p.id}>{p.name} · {roleName(p.roleId)}</option>)}
        </select>
      </Field>
      <Field label="New role">
        <select required value={f.newRoleId} onChange={set('newRoleId')}>
          <option value="">Choose…</option>
          {roles.filter((r) => r.id !== person?.roleId).map((r) => <option key={r.id} value={r.id}>{r.name}</option>)}
        </select>
      </Field>
      <Field label="New title (optional)"><input value={f.newTitle} onChange={set('newTitle')} /></Field>
      <p className="muted small">Access not in the new role is revoked — including request-based grants.</p>
      <button className="btn primary">Transfer mover</button>
    </form>
  )
}

function LeaverForm({ people, onSubmit }) {
  const [f, setF] = useState({ identityId: people[0]?.id || '', endDate: '' })
  const set = (k) => (e) => setF({ ...f, [k]: e.target.value })
  return (
    <form className="form" onSubmit={(e) => {
      e.preventDefault()
      if (confirm('Terminate this identity and revoke all access?')) onSubmit(f)
    }}>
      <Field label="Identity">
        <select value={f.identityId} onChange={set('identityId')}>
          {people.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
        </select>
      </Field>
      <Field label="Last day"><input type="date" value={f.endDate} onChange={set('endDate')} /></Field>
      <p className="muted small">Disables the account, revokes every grant and cancels open requests.</p>
      <button className="btn danger">Terminate leaver</button>
    </form>
  )
}
