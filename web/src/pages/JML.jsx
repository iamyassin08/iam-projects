import { useMemo, useState } from 'react'
import { Users, UserPlus, ArrowRightLeft, UserX, Search } from 'lucide-react'
import { api, fmtDate } from '../api.js'
import { makeLookups } from '../lookups.js'
import { useLoad, PageHeader, Card, Badge, Button, ErrorBox, Loading, Field, ask, toast, Avatar, Seg, usePreline, Tooltip } from '../ui.jsx'

const evTone = { joiner: 'ok', mover: 'warn', leaver: 'bad', rehire: 'info' }

export default function JML() {
  const [data, reload, error] = useLoad({ catalog: api.catalog, people: api.identities, events: api.jmlEvents })
  const [tab, setTab] = useState('joiner')
  const [selected, setSelected] = useState(null)
  const [access, setAccess] = useState([])
  const [q, setQ] = useState('')
  const L = useMemo(() => makeLookups(data?.catalog, data?.people), [data])
  usePreline([data, access])

  async function pick(p) {
    setSelected(p)
    try { setAccess(await api.access(p.id)) } catch (e) { toast(e.message, 'err') }
  }
  async function run(fn, msg) {
    try {
      const res = await fn()
      await reload()
      if (selected) setAccess(await api.access(selected.id).catch(() => []))
      toast(msg(res))
    } catch (e) { toast(e.message, 'err') }
  }

  if (!data) return <><ErrorBox error={error} /><Loading /></>
  const active = data.people.filter((p) => p.status === 'active')
  const shown = data.people.filter((p) => !q || `${p.name} ${p.email} ${p.department}`.toLowerCase().includes(q.toLowerCase()))

  return (
    <div className="space-y-6">
      <PageHeader icon={Users} eyebrow="Identity lifecycle · NIST AC-2" title="Joiner · Mover · Leaver"
        desc="HR is the source of truth. A role defines birthright access; movers lose everything outside the new role, including request-based extras; leavers are disabled and revoked the same day. The same code path serves SCIM, so an IdP push is governed exactly like an analyst action." />
      <ErrorBox error={error} />

      <div className="grid gap-6 lg:grid-cols-5">
        <Card className="lg:col-span-2" title="Lifecycle event" delay={60}
          actions={<Seg value={tab} onChange={setTab} options={[{ value: 'joiner', label: 'Joiner' }, { value: 'mover', label: 'Mover' }, { value: 'leaver', label: 'Leaver' }]} />}>
          <div key={tab} className="animate-fade-in">
            {tab === 'joiner' && <JoinerForm roles={data.catalog.roles} people={active} onSubmit={(b) => run(() => api.joiner(b), (r) => `${r.name} onboarded with birthright access`)} />}
            {tab === 'mover' && <MoverForm roles={data.catalog.roles} people={active} L={L} onSubmit={(b) => run(() => api.mover(b), (r) => `Moved: +${r.granted.length} / −${r.revoked.length} entitlements`)} />}
            {tab === 'leaver' && <LeaverForm people={active} onSubmit={(b) => run(() => api.leaver(b), (r) => `Disabled; revoked ${r.revoked.length} entitlements`)} />}
          </div>
        </Card>

        <Card className="lg:col-span-3" title="Lifecycle history" subtitle="Every event shows exactly what was granted and revoked" delay={120}>
          <ol className="relative max-h-[430px] space-y-4 overflow-y-auto border-s border-white/10 ps-5">
            {data.events.slice(0, 20).map((ev, i) => (
              <li key={ev.id} className="relative animate-fade-up" style={{ animationDelay: `${i * 30}ms` }}>
                <span className={`absolute -start-[26px] top-1 size-2.5 rounded-full ring-4 ring-zinc-900 ${ev.type === 'leaver' ? 'bg-rose-400' : ev.type === 'mover' ? 'bg-amber-400' : 'bg-emerald-400'}`} />
                <div className="flex flex-wrap items-center gap-2">
                  <Badge tone={evTone[ev.type]}>{ev.type}</Badge>
                  <span className="text-sm text-zinc-100">{ev.summary}</span>
                </div>
                <div className="mt-1 text-xs text-zinc-500">{fmtDate(ev.at)}</div>
                {(ev.granted.length > 0 || ev.revoked.length > 0) && (
                  <div className="mt-1.5 flex flex-wrap gap-1">
                    {ev.granted.map((e) => <span key={'g' + e} className="rounded bg-emerald-500/10 px-1.5 py-0.5 text-[11px] text-emerald-300">+ {L.entName(e)}</span>)}
                    {ev.revoked.map((e) => <span key={'r' + e} className="rounded bg-rose-500/10 px-1.5 py-0.5 text-[11px] text-rose-300">− {L.entName(e)}</span>)}
                  </div>
                )}
              </li>
            ))}
          </ol>
        </Card>
      </div>

      <Card title="Directory" subtitle="Click a person to see their effective access and where each grant came from" delay={180} pad={false}
        actions={<div className="relative"><Search className="pointer-events-none absolute start-2.5 top-2.5 size-4 text-zinc-500" /><input className="input w-56 ps-8" placeholder="Search people…" value={q} onChange={(e) => setQ(e.target.value)} /></div>}>
        <div className="overflow-x-auto">
          <table className="min-w-full">
            <thead><tr><th className="th ps-5">Person</th><th className="th">Title</th><th className="th">Role</th><th className="th">Manager</th><th className="th">Status</th><th className="th">Grants</th><th className="th pe-5">Source ID</th></tr></thead>
            <tbody>
              {shown.map((p) => (
                <tr key={p.id} onClick={() => pick(p)} className={`row cursor-pointer ${selected?.id === p.id ? 'bg-violet-500/[0.07]' : ''}`}>
                  <td className="td ps-5"><div className="flex items-center gap-3"><Avatar name={p.name} /><div><div className="font-medium text-zinc-100">{p.name}</div><div className="text-xs text-zinc-500">{p.email}</div></div></div></td>
                  <td className="td text-zinc-300">{p.title || '—'}<div className="text-xs text-zinc-500">{p.department}</div></td>
                  <td className="td text-zinc-300">{L.roleName(p.roleId)}</td>
                  <td className="td text-zinc-400">{p.manager || '—'}</td>
                  <td className="td"><Badge tone={p.status === 'active' ? 'ok' : 'bad'} dot>{p.status}</Badge></td>
                  <td className="td tabular-nums text-zinc-300">{p.grantCount}</td>
                  <td className="td pe-5"><span className="code">{p.externalId || p.id}</span></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>

      {selected && (
        <Card key={selected.id} title={`Effective access · ${L.person(selected.id)}`} subtitle="role = birthright · request = approved exception · jit = time-boxed elevation">
          {access.length === 0 ? <p className="text-sm text-zinc-500">No access.</p> : (
            <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
              {access.map((g, i) => {
                const e = L.ent[g.entitlementId]
                return (
                  <div key={g.entitlementId} className="flex items-center justify-between gap-2 rounded-xl border border-white/[0.07] bg-white/[0.02] px-3 py-2.5 animate-scale-in" style={{ animationDelay: `${i * 35}ms` }}>
                    <div className="min-w-0">
                      <div className="truncate text-sm text-zinc-100">{e?.name}</div>
                      <div className="text-[11px] text-zinc-500">{L.sysOf(g.entitlementId)}{g.lastUsed && ` · used ${new Date(g.lastUsed).toLocaleDateString()}`}</div>
                    </div>
                    <div className="flex shrink-0 gap-1">
                      {e?.privileged && <Tooltip tip="Privileged entitlement"><Badge tone="bad">priv</Badge></Tooltip>}
                      <Badge tone={g.source === 'role' ? 'neutral' : g.source === 'jit' ? 'info' : 'violet'}>{g.source}</Badge>
                    </div>
                  </div>
                )
              })}
            </div>
          )}
        </Card>
      )}
    </div>
  )
}

function JoinerForm({ roles, people, onSubmit }) {
  const [f, setF] = useState({ name: '', title: '', manager: '', roleId: roles[0]?.id || '', email: '', startDate: '' })
  const set = (k) => (e) => setF({ ...f, [k]: e.target.value })
  const role = roles.find((r) => r.id === f.roleId)
  return (
    <form className="grid gap-4 sm:grid-cols-2" onSubmit={(e) => { e.preventDefault(); onSubmit(f); setF({ ...f, name: '', title: '', email: '' }) }}>
      <Field label="Full name" required><input required className="input" value={f.name} onChange={set('name')} placeholder="Jordan Reyes" /></Field>
      <Field label="Job title"><input className="input" value={f.title} onChange={set('title')} placeholder="Software Engineer I" /></Field>
      <Field label="Role" required>
        <select className="input" value={f.roleId} onChange={set('roleId')}>{roles.map((r) => <option key={r.id} value={r.id}>{r.name}</option>)}</select>
      </Field>
      <Field label="Manager">
        <select className="input" value={f.manager} onChange={set('manager')}><option value="">—</option>{people.map((p) => <option key={p.id}>{p.name}</option>)}</select>
      </Field>
      <Field label="Email" hint="Defaults to first.last@demo.local"><input className="input" value={f.email} onChange={set('email')} /></Field>
      <Field label="Start date"><input type="date" className="input" value={f.startDate} onChange={set('startDate')} /></Field>
      <div className="sm:col-span-2 flex flex-wrap items-center justify-between gap-3">
        {role && <p className="text-xs text-zinc-500">Birthright: {role.entitlements.length} entitlements from <span className="text-zinc-300">{role.name}</span></p>}
        <Button type="submit"><UserPlus className="size-4" /> Onboard joiner</Button>
      </div>
    </form>
  )
}

function MoverForm({ roles, people, L, onSubmit }) {
  const [f, setF] = useState({ identityId: people[0]?.id || '', newRoleId: '', newTitle: '' })
  const set = (k) => (e) => setF({ ...f, [k]: e.target.value })
  const person = people.find((p) => p.id === f.identityId)
  const oldR = L.role[person?.roleId], newR = L.role[f.newRoleId]
  const lose = oldR && newR ? oldR.entitlements.filter((e) => !newR.entitlements.includes(e)) : []
  const gain = oldR && newR ? newR.entitlements.filter((e) => !oldR.entitlements.includes(e)) : []
  return (
    <form className="grid gap-4" onSubmit={(e) => { e.preventDefault(); onSubmit(f) }}>
      <Field label="Identity" required>
        <select className="input" value={f.identityId} onChange={(e) => setF({ ...f, identityId: e.target.value, newRoleId: '' })}>
          {people.map((p) => <option key={p.id} value={p.id}>{p.name} · {L.roleName(p.roleId)}</option>)}
        </select>
      </Field>
      <Field label="New role" required>
        <select required className="input" value={f.newRoleId} onChange={set('newRoleId')}>
          <option value="">Choose…</option>
          {roles.filter((r) => r.id !== person?.roleId).map((r) => <option key={r.id} value={r.id}>{r.name}</option>)}
        </select>
      </Field>
      <Field label="New title"><input className="input" value={f.newTitle} onChange={set('newTitle')} /></Field>
      {newR && (
        <div className="rounded-xl border border-white/[0.07] bg-white/[0.02] p-3 text-xs animate-fade-in">
          <div className="mb-1.5 font-semibold text-zinc-300">Preview (birthright only)</div>
          <div className="flex flex-wrap gap-1">
            {gain.map((e) => <span key={e} className="rounded bg-emerald-500/10 px-1.5 py-0.5 text-emerald-300">+ {L.entName(e)}</span>)}
            {lose.map((e) => <span key={e} className="rounded bg-rose-500/10 px-1.5 py-0.5 text-rose-300">− {L.entName(e)}</span>)}
          </div>
          <p className="mt-2 text-zinc-500">Request-based access outside the new role is revoked too.</p>
        </div>
      )}
      <div className="flex justify-end"><Button type="submit"><ArrowRightLeft className="size-4" /> Transfer mover</Button></div>
    </form>
  )
}

function LeaverForm({ people, onSubmit }) {
  const [f, setF] = useState({ identityId: people[0]?.id || '', endDate: '' })
  const set = (k) => (e) => setF({ ...f, [k]: e.target.value })
  return (
    <form className="grid gap-4" onSubmit={async (e) => {
      e.preventDefault()
      const p = people.find((x) => x.id === f.identityId)
      const ok = await ask({ title: `Terminate ${p?.name}?`, message: 'Disables the identity, revokes every grant, ends live JIT sessions and cancels open requests. Accounts in manually provisioned systems stay enabled until the ticket is worked; reconciliation will flag them.', input: false, confirm: 'Terminate', tone: 'danger' })
      if (ok) onSubmit(f)
    }}>
      <Field label="Identity" required>
        <select className="input" value={f.identityId} onChange={set('identityId')}>{people.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}</select>
      </Field>
      <Field label="Last day"><input type="date" className="input" value={f.endDate} onChange={set('endDate')} /></Field>
      <div className="flex justify-end"><Button type="submit" variant="danger"><UserX className="size-4" /> Terminate leaver</Button></div>
    </form>
  )
}
