import { useEffect, useMemo, useState } from 'react'
import { ClipboardCheck, Plus, Check, X, Download, Lock, AlertTriangle, Clock } from 'lucide-react'
import { api, fmtDay, ago, downloadFile, toCSV } from '../api.js'
import { makeLookups } from '../lookups.js'
import { useLoad, PageHeader, Card, Badge, Button, ErrorBox, Loading, Field, ask, toast, Avatar, Progress, Modal, openModal, closeModal, Empty, Tooltip, usePreline, Seg } from '../ui.jsx'

const scopeLabel = { all: 'All access', privileged: 'Privileged access', requested: 'Exceptions (requested)', system: 'Single application' }

export default function Certifications() {
  const [data, reload, error] = useLoad({ catalog: api.catalog, people: api.identities, campaigns: api.campaigns })
  const [sel, setSel] = useState(null)
  const [detail, setDetail] = useState(null)
  const [view, setView] = useState('pending')
  const L = useMemo(() => makeLookups(data?.catalog, data?.people), [data])
  usePreline([data, detail])

  useEffect(() => {
    if (!sel && data?.campaigns?.length) setSel(data.campaigns.find((c) => c.status === 'active')?.id || data.campaigns[0].id)
  }, [data, sel])
  useEffect(() => {
    if (!sel) return
    api.campaign(sel).then(setDetail).catch((e) => toast(e.message, 'err'))
  }, [sel, data])

  async function refresh() { await reload() }

  async function decide(it, decision) {
    let comment = ''
    if (decision === 'revoke') {
      comment = await ask({ title: `Revoke ${L.entName(it.entitlementId)}?`, message: `Access is removed from ${L.person(it.identityId)} immediately. ${it.source === 'role' ? 'This is birthright access, so an exclusion is recorded and role re-syncs will not re-grant it.' : ''}`, label: 'Reason', required: true, confirm: 'Revoke access', tone: 'danger' })
      if (comment === null) return
    } else if (it.sod) {
      comment = await ask({ title: 'Keep a conflicting grant?', message: `This grant is part of ${it.sod}. Keeping it needs a written justification.`, label: 'Justification', required: true, confirm: 'Keep' })
      if (comment === null) return
    }
    try {
      await api.decideItem(it.campaignId, it.id, decision, comment)
      await refresh()
      toast(decision === 'keep' ? 'Certified: access kept' : 'Revoked and removed', decision === 'keep' ? 'ok' : 'warn')
    } catch (e) { toast(e.message, 'err') }
  }

  async function close(c) {
    const pending = c.total - c.decided
    const ok = await ask({ title: `Close “${c.name}”?`, message: c.autoRevoke && pending ? `${pending} undecided item${pending > 1 ? 's' : ''} will be revoked automatically (revoke on non-response).` : 'The campaign becomes read-only evidence.', input: false, confirm: 'Close campaign', tone: pending && c.autoRevoke ? 'danger' : 'primary' })
    if (!ok) return
    try { await api.closeCampaign(c.id); await refresh(); toast('Campaign closed') } catch (e) { toast(e.message, 'err') }
  }

  function exportEvidence() {
    if (!detail) return
    const rows = detail.items.map((it) => ({
      campaign: detail.campaign.name, item: it.id, person: L.person(it.identityId), application: L.sysOf(it.entitlementId), entitlement: L.entName(it.entitlementId),
      source: it.source, privileged: it.privileged, sod: it.sod || '', lastUsed: it.lastUsed || '', reviewer: it.reviewer, decision: it.decision,
      comment: it.comment || '', decidedBy: it.decidedBy || '', decidedAt: it.decidedAt || '',
    }))
    downloadFile(`${detail.campaign.id}-evidence.csv`, toCSV(rows, Object.keys(rows[0] || { campaign: 1 })), 'text/csv')
  }

  if (!data) return <><ErrorBox error={error} /><Loading /></>
  const c = detail?.campaign
  const items = (detail?.items || []).filter((it) => view === 'all' || (view === 'pending' ? it.decision === 'pending' : it.decision !== 'pending'))
  const byReviewer = items.reduce((a, it) => ({ ...a, [it.reviewer]: [...(a[it.reviewer] || []), it] }), {})

  return (
    <div className="space-y-6">
      <PageHeader icon={ClipboardCheck} eyebrow="User access review · SOX ITGC · NIST AC-2(j)" title="Access reviews"
        desc="A campaign snapshots every grant in scope and routes it to the person's manager to keep or revoke. Revocations take effect immediately; closing a campaign can revoke whatever nobody answered for. The CSV export is the evidence package an auditor samples.">
        <Button onClick={() => openModal('launch-modal')}><Plus className="size-4" /> Launch campaign</Button>
      </PageHeader>
      <ErrorBox error={error} />

      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
        {data.campaigns.map((x, i) => (
          <button key={x.id} type="button" onClick={() => setSel(x.id)}
            className={`panel group p-5 text-start transition-all duration-300 hover:-translate-y-0.5 animate-fade-up ${sel === x.id ? 'border-violet-500/50 ring-1 ring-violet-500/30' : 'hover:border-white/15'}`}
            style={{ animationDelay: `${i * 60}ms` }}>
            <div className="flex items-start justify-between gap-2">
              <div className="font-semibold text-zinc-100">{x.name}</div>
              {x.status === 'closed' ? <Badge tone="neutral"><Lock className="size-3" /> closed</Badge> : x.overdue ? <Badge tone="bad" dot>overdue</Badge> : <Badge tone="ok" dot>active</Badge>}
            </div>
            <div className="mt-1 text-xs text-zinc-500">{scopeLabel[x.scope]}{x.systemId && ` · ${L.sys[x.systemId]?.name}`} · due {fmtDay(x.dueDate)}</div>
            <div className="mt-4 flex items-end justify-between">
              <div className="font-display text-2xl font-bold text-white tabular-nums">{x.percent}%</div>
              <div className="text-xs text-zinc-400">{x.decided}/{x.total} decided · {x.revoked} revoked</div>
            </div>
            <Progress value={x.percent} tone={x.percent === 100 ? 'ok' : x.overdue ? 'bad' : 'violet'} className="mt-2" />
          </button>
        ))}
      </div>

      {c && (
        <Card key={c.id} title={c.name} subtitle={`${c.reviewers} reviewer${c.reviewers === 1 ? '' : 's'} · launched by ${c.createdBy} ${ago(c.createdAt)} · ${c.autoRevoke ? 'revoke on non-response' : 'no auto-revoke'}`}
          actions={<>
            <Seg value={view} onChange={setView} options={['pending', 'decided', 'all']} />
            <Button size="sm" variant="ghost" onClick={exportEvidence}><Download className="size-3.5" /> Evidence CSV</Button>
            {c.status === 'active' && <Button size="sm" variant="ghost" onClick={() => close(c)}><Lock className="size-3.5" /> Close</Button>}
          </>}>
          {items.length === 0 ? <Empty icon={Check}>{view === 'pending' ? 'All items decided.' : 'No items here.'}</Empty> : (
            <div className="space-y-6">
              {Object.entries(byReviewer).map(([rev, list]) => (
                <div key={rev}>
                  <div className="mb-2 flex items-center gap-2 text-xs text-zinc-400"><Avatar name={rev} size="size-6" /> Reviewer: <span className="font-semibold text-zinc-200">{rev}</span> · {list.length} item{list.length > 1 ? 's' : ''}</div>
                  <div className="overflow-x-auto rounded-xl border border-white/[0.06]">
                    <table className="min-w-full">
                      <thead className="bg-white/[0.02]"><tr><th className="th">Person</th><th className="th">Entitlement</th><th className="th">Source</th><th className="th">Last used</th><th className="th">Decision</th></tr></thead>
                      <tbody>
                        {list.map((it, i) => {
                          const stale = it.lastUsed && (Date.now() - new Date(it.lastUsed)) / 864e5 > 90
                          return (
                            <tr key={it.id} className="row animate-fade-in" style={{ animationDelay: `${i * 30}ms` }}>
                              <td className="td font-medium text-zinc-100">{L.person(it.identityId)}</td>
                              <td className="td">
                                <div className="text-zinc-200">{L.entName(it.entitlementId)}</div>
                                <div className="mt-0.5 flex flex-wrap items-center gap-1 text-xs text-zinc-500">{L.sysOf(it.entitlementId)}
                                  {it.privileged && <Badge tone="bad">privileged</Badge>}
                                  {it.sod && <Tooltip tip={`Part of SoD rule ${it.sod}`}><Badge tone="warn"><AlertTriangle className="size-3" /> {it.sod}</Badge></Tooltip>}
                                </div>
                              </td>
                              <td className="td"><Badge tone={it.source === 'role' ? 'neutral' : 'violet'}>{it.source}</Badge></td>
                              <td className="td text-xs">{it.lastUsed ? <span className={stale ? 'font-semibold text-amber-300' : 'text-zinc-400'}>{stale && <Clock className="me-1 inline size-3" />}{ago(it.lastUsed)}</span> : <span className="text-zinc-600">—</span>}</td>
                              <td className="td">
                                {it.decision === 'pending' && c.status === 'active' ? (
                                  <div className="flex gap-1.5">
                                    <Button size="sm" variant="success" onClick={() => decide(it, 'keep')}><Check className="size-3.5" /> Keep</Button>
                                    <Button size="sm" variant="ghost" onClick={() => decide(it, 'revoke')}><X className="size-3.5" /> Revoke</Button>
                                  </div>
                                ) : (
                                  <div>
                                    <Badge tone={it.decision === 'keep' ? 'ok' : it.decision === 'revoke' ? 'bad' : 'neutral'}>{it.decision}</Badge>
                                    {it.comment && <div className="mt-1 max-w-xs text-xs text-zinc-500">“{it.comment}” · {it.decidedBy}</div>}
                                  </div>
                                )}
                              </td>
                            </tr>
                          )
                        })}
                      </tbody>
                    </table>
                  </div>
                </div>
              ))}
            </div>
          )}
        </Card>
      )}

      <LaunchModal systems={data.catalog.systems} onDone={async (id) => { await refresh(); setSel(id) }} />
    </div>
  )
}

function LaunchModal({ systems, onDone }) {
  const [f, setF] = useState({ name: 'Q4 2026 user access review', scope: 'all', systemId: '', dueDays: 14, autoRevoke: true })
  const set = (k) => (e) => setF({ ...f, [k]: e.target.type === 'checkbox' ? e.target.checked : e.target.value })
  async function launch() {
    try {
      const c = await api.launchCampaign({ ...f, dueDays: Number(f.dueDays) })
      closeModal('launch-modal')
      toast(`Launched ${c.name}`)
      onDone(c.id)
    } catch (e) { toast(e.message, 'err') }
  }
  return (
    <Modal id="launch-modal" title="Launch an access review" size="md"
      footer={<><Button variant="ghost" data-hs-overlay="#launch-modal">Cancel</Button><Button onClick={launch}>Launch</Button></>}>
      <div className="grid gap-4">
        <Field label="Campaign name" required><input className="input" value={f.name} onChange={set('name')} /></Field>
        <Field label="Scope" hint="JIT grants are excluded: they are already time-boxed and reviewed per session.">
          <select className="input" value={f.scope} onChange={set('scope')}>
            {Object.entries(scopeLabel).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
          </select>
        </Field>
        {f.scope === 'system' && (
          <Field label="Application" required>
            <select className="input" value={f.systemId} onChange={set('systemId')}><option value="">Choose…</option>{systems.map((s) => <option key={s.id} value={s.id}>{s.name}</option>)}</select>
          </Field>
        )}
        <Field label="Due in (days)"><input type="number" min={1} max={90} className="input" value={f.dueDays} onChange={set('dueDays')} /></Field>
        <label className="flex items-start gap-3 rounded-xl border border-white/[0.07] bg-white/[0.02] p-3">
          <input type="checkbox" checked={f.autoRevoke} onChange={set('autoRevoke')} className="mt-0.5 size-4 shrink-0 rounded border-white/20 bg-zinc-900 text-violet-600 focus:ring-violet-500" />
          <span className="text-sm text-zinc-300">Revoke on non-response<span className="block text-xs text-zinc-500">Undecided items are revoked when the campaign closes. Standard for SOX-scoped applications.</span></span>
        </label>
      </div>
    </Modal>
  )
}
