import { useMemo, useRef, useState } from 'react'
import { Timer, Zap, Siren, ShieldCheck, Square, Plus, Trash2, ClipboardCheck } from 'lucide-react'
import { api, fmtDate, until, ago } from '../api.js'
import { makeLookups } from '../lookups.js'
import { useLoad, useTick, PageHeader, Card, Badge, Button, ErrorBox, Loading, Field, ask, toast, Avatar, Modal, openModal, closeModal, Empty, Progress, usePreline, Stat } from '../ui.jsx'

export default function PAM() {
  const [data, reload, error] = useLoad({ catalog: api.catalog, people: api.identities, pam: api.pam }, [], { poll: 10000 })
  const [act, setAct] = useState(null) // { identityId, entitlementId, max, breakGlass }
  const L = useMemo(() => makeLookups(data?.catalog, data?.people), [data])
  const lastPoll = useRef(0)
  useTick(1000)
  usePreline([data])

  if (!data) return <><ErrorBox error={error} /><Loading /></>
  const { sessions, eligibility } = data.pam
  const live = sessions.filter((s) => s.status === 'active')
  const unreviewed = sessions.filter((s) => s.breakGlass && !s.reviewedBy && s.status !== 'active')
  const privEnts = data.catalog.entitlements.filter((e) => e.privileged)
  const active = data.people.filter((p) => p.status === 'active')

  // A live session past its window means the sweeper hasn't run yet; refresh shortly.
  if (live.some((s) => new Date(s.expiresAt) <= new Date()) && Date.now() - lastPoll.current > 4000) {
    lastPoll.current = Date.now()
    setTimeout(reload, 500)
  }

  function activate(el, breakGlass = false) {
    setAct({ identityId: el?.identityId || '', entitlementId: el?.entitlementId || '', max: breakGlass ? data.pam.breakGlassMaxMinutes : el.maxMinutes, breakGlass })
    setTimeout(() => openModal('elevate-modal'), 0)
  }
  async function end(s) {
    const ok = await ask({ title: 'End elevation now?', message: `${L.person(s.identityId)} loses ${L.entName(s.entitlementId)} immediately.`, input: false, confirm: 'End session', tone: 'danger' })
    if (!ok) return
    try { await api.endSession(s.id); await reload(); toast('Elevation ended') } catch (e) { toast(e.message, 'err') }
  }
  async function review(s) {
    const notes = await ask({ title: `Review break-glass ${s.id}`, message: <>Confirm the emergency was real and the access was used appropriately. <span className="text-zinc-500">Justification given: “{s.justification}”</span></>, label: 'Review notes', placeholder: 'Matched INC0046001; actions in AD logs limited to federation trust reset', required: true, confirm: 'Mark reviewed' })
    if (notes === null) return
    try { await api.reviewSession(s.id, notes); await reload(); toast('Break-glass session reviewed') } catch (e) { toast(e.message, 'err') }
  }
  async function removeEl(el) {
    const ok = await ask({ title: 'Remove eligibility?', message: `${L.person(el.identityId)} will no longer be able to activate ${L.entName(el.entitlementId)}.`, input: false, confirm: 'Remove', tone: 'danger' })
    if (!ok) return
    try { await api.removeEligibility(el.identityId, el.entitlementId); await reload(); toast('Eligibility removed') } catch (e) { toast(e.message, 'err') }
  }

  return (
    <div className="space-y-6">
      <PageHeader icon={Timer} eyebrow="Privileged access management · NIST AC-6(5) · AC-2(2)" title="Just-in-time access"
        desc="Zero standing privilege: eligible people activate an admin role for a bounded window, with a justification and a change or incident ticket. A Go goroutine sweeps expired grants every 15 seconds. Break-glass skips eligibility for emergencies, is capped at 60 minutes, and must be reviewed afterwards.">
        <Button variant="danger" onClick={() => activate(null, true)}><Siren className="size-4" /> Break-glass</Button>
      </PageHeader>
      <ErrorBox error={error} />

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <Stat label="Live elevations" value={live.length} icon={Zap} tone="info" />
        <Stat label="Eligible assignments" value={eligibility.length} icon={ShieldCheck} tone="violet" delay={60} />
        <Stat label="Sessions (all time)" value={sessions.length} icon={Timer} tone="ok" delay={120} />
        <Stat label="Break-glass to review" value={unreviewed.length} icon={Siren} tone={unreviewed.length ? 'bad' : 'ok'} delay={180} />
      </div>

      <Card title="Live elevations" subtitle="Auto-refreshes; grants are removed the moment the window closes" delay={60}>
        {live.length === 0 ? <Empty icon={ShieldCheck}>No standing admin right now. Activate an eligible role below.</Empty> : (
          <div className="grid gap-3 md:grid-cols-2">
            {live.map((s) => {
              const total = s.minutes * 60, left = Math.max(0, (new Date(s.expiresAt) - Date.now()) / 1000)
              return (
                <div key={s.id} className={`relative overflow-hidden rounded-xl border p-4 animate-scale-in ${s.breakGlass ? 'border-rose-500/40 bg-rose-500/[0.05]' : 'border-sky-500/30 bg-sky-500/[0.04]'}`}>
                  <span className={`absolute end-4 top-4 size-2 rounded-full ${s.breakGlass ? 'bg-rose-400' : 'bg-sky-400'}`}><span className={`absolute inset-0 rounded-full animate-ping-slow ${s.breakGlass ? 'bg-rose-400' : 'bg-sky-400'}`} /></span>
                  <div className="flex items-center gap-3">
                    <Avatar name={L.person(s.identityId)} />
                    <div>
                      <div className="text-sm font-semibold text-zinc-100">{L.person(s.identityId)}</div>
                      <div className="text-xs text-zinc-400">{L.entName(s.entitlementId)} · {L.sysOf(s.entitlementId)}</div>
                    </div>
                  </div>
                  <div className="mt-3 flex items-end justify-between">
                    <div className="font-mono text-2xl font-bold tabular-nums text-white">{until(s.expiresAt)}</div>
                    <div className="text-end text-xs text-zinc-500">{s.breakGlass ? <Badge tone="bad">break-glass</Badge> : <span className="code">{s.ticket}</span>}<div className="mt-1">of {s.minutes} min</div></div>
                  </div>
                  <Progress value={(left / total) * 100} tone={s.breakGlass ? 'bad' : 'violet'} className="mt-2" />
                  <div className="mt-3 flex items-center justify-between gap-2">
                    <p className="truncate text-xs italic text-zinc-500">“{s.justification}”</p>
                    <Button size="sm" variant="ghost" onClick={() => end(s)}><Square className="size-3" /> End now</Button>
                  </div>
                </div>
              )
            })}
          </div>
        )}
      </Card>

      <div className="grid gap-6 lg:grid-cols-2">
        <Card title="Eligible assignments" subtitle="Who may activate which privileged role, and for how long" delay={120} pad={false}
          actions={<Button size="sm" variant="ghost" onClick={() => openModal('elig-modal')}><Plus className="size-3.5" /> Add</Button>}>
          <div className="overflow-x-auto">
            <table className="min-w-full">
              <thead><tr><th className="th ps-5">Person</th><th className="th">Role</th><th className="th">Max</th><th className="th pe-5" /></tr></thead>
              <tbody>
                {eligibility.map((el) => {
                  const running = live.some((s) => s.identityId === el.identityId && s.entitlementId === el.entitlementId)
                  return (
                    <tr key={el.identityId + el.entitlementId} className="row">
                      <td className="td ps-5"><div className="flex items-center gap-2"><Avatar name={L.person(el.identityId)} size="size-7" /><span className="text-zinc-100">{L.person(el.identityId)}</span></div></td>
                      <td className="td"><div className="text-zinc-200">{L.entName(el.entitlementId)}</div><div className="text-xs text-zinc-500">{L.sysOf(el.entitlementId)}</div></td>
                      <td className="td text-zinc-400">{el.maxMinutes}m</td>
                      <td className="td pe-5">
                        <div className="flex justify-end gap-1.5">
                          <Button size="sm" disabled={running} onClick={() => activate(el)}><Zap className="size-3.5" /> {running ? 'Active' : 'Activate'}</Button>
                          <Button size="sm" variant="subtle" aria-label="Remove eligibility" onClick={() => removeEl(el)}><Trash2 className="size-3.5" /></Button>
                        </div>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        </Card>

        <Card title="Session history" subtitle="Every elevation, with ticket and outcome" delay={180}>
          <ul className="max-h-[420px] space-y-3 overflow-y-auto">
            {sessions.filter((s) => s.status !== 'active').map((s) => (
              <li key={s.id} className={`rounded-xl border p-3 ${s.breakGlass && !s.reviewedBy ? 'border-rose-500/30 bg-rose-500/[0.04]' : 'border-white/[0.06] bg-white/[0.02]'}`}>
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="text-sm text-zinc-100"><span className="font-semibold">{L.person(s.identityId)}</span> · {L.entName(s.entitlementId)}</div>
                  <div className="flex gap-1">{s.breakGlass && <Badge tone="bad">break-glass</Badge>}<Badge tone={s.status === 'expired' ? 'neutral' : 'warn'}>{s.status}</Badge></div>
                </div>
                <div className="mt-1 text-xs text-zinc-500">{s.id} · {fmtDate(s.startedAt)} · {s.minutes} min {s.ticket && <>· <span className="code">{s.ticket}</span></>}</div>
                <p className="mt-1 text-xs italic text-zinc-400">“{s.justification}”</p>
                {s.breakGlass && (s.reviewedBy
                  ? <p className="mt-1.5 text-xs text-emerald-300">Reviewed by {s.reviewedBy}: {s.reviewNotes}</p>
                  : <Button size="sm" className="mt-2" onClick={() => review(s)}><ClipboardCheck className="size-3.5" /> Review now</Button>)}
              </li>
            ))}
          </ul>
        </Card>
      </div>

      <ElevateModal act={act} data={data} L={L} privEnts={privEnts} active={active} onDone={reload} />
      <EligModal privEnts={privEnts} active={active} onDone={reload} />
    </div>
  )
}

function ElevateModal({ act, data, L, privEnts, active, onDone }) {
  const [f, setF] = useState({ minutes: 30, justification: '', ticket: '' })
  const [who, setWho] = useState({ identityId: '', entitlementId: '' })
  const bg = act?.breakGlass
  const identityId = bg ? who.identityId : act?.identityId
  const entitlementId = bg ? who.entitlementId : act?.entitlementId
  async function go() {
    try {
      await api.elevate({ identityId, entitlementId, minutes: Number(f.minutes), justification: f.justification, ticket: f.ticket, breakGlass: !!bg })
      closeModal('elevate-modal')
      setF({ minutes: 30, justification: '', ticket: '' })
      await onDone()
      toast(bg ? 'Break-glass access granted; review required afterwards' : 'Elevation active', bg ? 'warn' : 'ok')
    } catch (e) { toast(e.message, 'err') }
  }
  return (
    <Modal id="elevate-modal" size="md" title={bg ? 'Break-glass emergency access' : `Activate ${L.entName(entitlementId)}`}
      footer={<><Button variant="ghost" data-hs-overlay="#elevate-modal">Cancel</Button><Button variant={bg ? 'danger' : 'primary'} onClick={go}><Zap className="size-4" /> {bg ? 'Grant emergency access' : 'Activate'}</Button></>}>
      <div className="grid gap-4">
        {bg ? (
          <>
            <div className="rounded-xl border border-rose-500/30 bg-rose-500/10 p-3 text-xs text-rose-200">Bypasses eligibility and ticket checks. Capped at {data.pam.breakGlassMaxMinutes} minutes, fully audited, and flagged by control C9 until someone reviews it.</div>
            <Field label="Person" required><select className="input" value={who.identityId} onChange={(e) => setWho({ ...who, identityId: e.target.value })}><option value="">Choose…</option>{active.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}</select></Field>
            <Field label="Privileged role" required><select className="input" value={who.entitlementId} onChange={(e) => setWho({ ...who, entitlementId: e.target.value })}><option value="">Choose…</option>{privEnts.map((e) => <option key={e.id} value={e.id}>{e.name} · {L.sys[e.systemId]?.name}</option>)}</select></Field>
          </>
        ) : (
          <div className="flex items-center gap-3 rounded-xl border border-white/[0.07] bg-white/[0.02] p-3"><Avatar name={L.person(identityId)} /><div className="text-sm"><div className="font-semibold text-zinc-100">{L.person(identityId)}</div><div className="text-xs text-zinc-500">Eligible for up to {act?.max} minutes</div></div></div>
        )}
        <Field label={`Duration: ${f.minutes} minutes`}>
          <input type="range" min={5} max={act?.max || 60} step={5} value={Math.min(f.minutes, act?.max || 60)} onChange={(e) => setF({ ...f, minutes: e.target.value })} className="w-full accent-violet-500" />
        </Field>
        {!bg && <Field label="Change / incident ticket" required hint="Format CHG, INC or RITM plus digits, e.g. CHG0012345"><input className="input font-mono" value={f.ticket} onChange={(e) => setF({ ...f, ticket: e.target.value })} placeholder="CHG0012345" /></Field>}
        <Field label="Justification" required><textarea rows={2} className="input" value={f.justification} onChange={(e) => setF({ ...f, justification: e.target.value })} placeholder={bg ? 'IdP outage: restore federation trust' : 'Rotate prod KMS keys in approved window'} /></Field>
      </div>
    </Modal>
  )
}

function EligModal({ privEnts, active, onDone }) {
  const [f, setF] = useState({ identityId: '', entitlementId: '', maxMinutes: 60 })
  async function add() {
    try { await api.addEligibility({ ...f, maxMinutes: Number(f.maxMinutes) }); closeModal('elig-modal'); await onDone(); toast('Eligibility added') } catch (e) { toast(e.message, 'err') }
  }
  return (
    <Modal id="elig-modal" size="md" title="Add JIT eligibility"
      footer={<><Button variant="ghost" data-hs-overlay="#elig-modal">Cancel</Button><Button onClick={add}><Plus className="size-4" /> Add</Button></>}>
      <div className="grid gap-4">
        <Field label="Person" required><select className="input" value={f.identityId} onChange={(e) => setF({ ...f, identityId: e.target.value })}><option value="">Choose…</option>{active.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}</select></Field>
        <Field label="Privileged role" required><select className="input" value={f.entitlementId} onChange={(e) => setF({ ...f, entitlementId: e.target.value })}><option value="">Choose…</option>{privEnts.map((e) => <option key={e.id} value={e.id}>{e.name}</option>)}</select></Field>
        <Field label="Max activation (minutes)" hint="15 to 480"><input type="number" min={15} max={480} className="input" value={f.maxMinutes} onChange={(e) => setF({ ...f, maxMinutes: e.target.value })} /></Field>
      </div>
    </Modal>
  )
}
