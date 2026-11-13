import { useMemo, useState } from 'react'
import { Radar, ChevronDown, Power, UserCheck, Link2, Clock, Trash2, Ghost, Skull, Bot, CheckCircle2 } from 'lucide-react'
import { api, ago } from '../api.js'
import { makeLookups } from '../lookups.js'
import { useLoad, PageHeader, Card, Badge, Button, ErrorBox, Loading, ask, toast, Avatar, Progress, Seg, Stat, usePreline, levelTone, Empty } from '../ui.jsx'

const findingMeta = {
  orphan: { tone: 'bad', icon: Ghost, label: 'Orphan' },
  rogue: { tone: 'bad', icon: Skull, label: 'Rogue' },
  'unowned-service': { tone: 'warn', icon: Bot, label: 'Unowned service' },
  ok: { tone: 'ok', icon: CheckCircle2, label: 'In sync' },
  disabled: { tone: 'neutral', icon: Power, label: 'Disabled' },
}

export default function Risk() {
  const [data, reload, error] = useLoad({ catalog: api.catalog, people: api.identities, risk: api.risk, recon: api.recon })
  const [tab, setTab] = useState('risk')
  const L = useMemo(() => makeLookups(data?.catalog, data?.people), [data])
  usePreline([data, tab])

  async function act(a, action) {
    let body = { action }
    if (action === 'assign-owner') {
      const owner = await ask({ title: `Assign an owner to ${a.accountName}`, message: 'Service accounts need an accountable human who answers for them in reviews.', input: 'text', label: 'Owner', placeholder: 'Omar Farouk', required: true, confirm: 'Next' })
      if (!owner) return
      body.owner = owner
    }
    const verb = { disable: 'Disable', 'assign-owner': 'Assign owner for', adopt: 'Adopt' }[action]
    const reason = await ask({
      title: `${verb} ${a.accountName}`,
      message: action === 'adopt' ? 'Adopting brings this access under governance as a retro-approved request. It will then appear in access reviews. Refused if it breaks an SoD rule.' : action === 'disable' ? `The account is disabled in ${L.sys[a.systemId]?.name}.` : null,
      label: 'Reason (recorded in the audit log)', required: true, confirm: verb, tone: action === 'disable' ? 'danger' : 'primary',
    })
    if (reason === null) return
    try { await api.accountAction(a.id, { ...body, reason }); await reload(); toast('Remediated and audited') } catch (e) { toast(e.message, 'err') }
  }
  async function revokeDormant(d) {
    const reason = await ask({ title: `Revoke ${L.entName(d.entitlementId)}?`, message: `${L.person(d.identityId)} hasn't used it in ${d.daysUnused} days.${d.privileged ? ' For admin rights, consider JIT eligibility instead of standing access.' : ''}`, label: 'Reason', defaultValue: `Unused for ${d.daysUnused} days`, required: true, confirm: 'Revoke', tone: 'danger' })
    if (reason === null) return
    try { await api.revokeGrant({ identityId: d.identityId, entitlementId: d.entitlementId, reason }); await reload(); toast('Dormant access revoked') } catch (e) { toast(e.message, 'err') }
  }

  if (!data) return <><ErrorBox error={error} /><Loading /></>
  const { risk, recon } = data
  const findings = recon.accounts.filter((a) => !['ok', 'disabled'].includes(a.finding)).length

  return (
    <div className="space-y-6">
      <PageHeader icon={Radar} eyebrow="Identity risk · reconciliation · NIST AC-2(3), AC-6(7)" title="Risk & reconciliation"
        desc="Reconciliation compares what IAM granted with what actually exists in each application, surfacing orphaned accounts, rogue access created outside IAM, ownerless service accounts and dormant entitlements. Risk scores are an additive, explainable model: every point traces to a factor you can fix." />
      <ErrorBox error={error} />

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <Stat label="Average identity risk" value={risk.average} suffix="/100" icon={Radar} tone={risk.average >= 30 ? 'warn' : 'ok'} />
        <Stat label="High or critical" value={risk.distribution.high + risk.distribution.critical} icon={Skull} tone="bad" delay={60} />
        <Stat label="Account drift findings" value={findings} icon={Ghost} tone={findings ? 'bad' : 'ok'} delay={120} />
        <Stat label={`Dormant grants (${recon.dormantDays}d+)`} value={recon.dormant.length} icon={Clock} tone={recon.dormant.length ? 'warn' : 'ok'} delay={180} />
      </div>

      <Seg value={tab} onChange={setTab} options={[{ value: 'risk', label: 'Risk scores' }, { value: 'recon', label: `Reconciliation · ${findings}` }, { value: 'dormant', label: `Dormant access · ${recon.dormant.length}` }]} />

      {tab === 'risk' && (
        <Card title="Identity risk" subtitle="Expand anyone to see exactly why they score what they do" delay={40}>
          <div className="hs-accordion-group space-y-2" data-hs-accordion-always-open="">
            {risk.identities.map((r, i) => (
              <div key={r.identityId} id={`risk-${r.identityId}`} className={`hs-accordion rounded-xl border border-white/[0.07] bg-white/[0.02] transition-colors hover:border-white/15 animate-fade-up ${i === 0 ? 'active' : ''}`} style={{ animationDelay: `${i * 40}ms` }}>
                <button type="button" className="hs-accordion-toggle flex w-full items-center gap-4 px-4 py-3 text-start" aria-expanded={i === 0} aria-controls={`risk-body-${r.identityId}`}>
                  <Avatar name={r.name} />
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-2"><span className="font-medium text-zinc-100">{r.name}</span><span className="text-xs text-zinc-500">{L.roleName(r.roleId)} · {r.grants} grants · {r.privileged} privileged</span></div>
                    <Progress value={r.score} tone={r.score >= 50 ? 'bad' : r.score >= 25 ? 'warn' : 'ok'} className="mt-2 max-w-md" />
                  </div>
                  <div className="text-end"><div className="font-display text-xl font-bold tabular-nums text-white">{r.score}</div><Badge tone={levelTone[r.level]}>{r.level}</Badge></div>
                  <ChevronDown className="size-4 shrink-0 text-zinc-500 transition-transform duration-300 hs-accordion-active:rotate-180" />
                </button>
                <div id={`risk-body-${r.identityId}`} role="region" className={`hs-accordion-content w-full overflow-hidden transition-[height] duration-300 ${i === 0 ? '' : 'hidden'}`}>
                  <div className="px-4 pb-4 ps-16">
                    {r.factors.length === 0 ? <p className="text-sm text-emerald-300">No risk factors: role-based access only, all of it in use.</p> : (
                      <ul className="space-y-1.5">
                        {r.factors.map((f, j) => (
                          <li key={j} className="flex items-center justify-between gap-3 rounded-lg bg-zinc-950/50 px-3 py-2 text-sm">
                            <span className="text-zinc-300">{f.label}</span>
                            <span className="font-mono text-xs font-bold text-rose-300">+{f.points}</span>
                          </li>
                        ))}
                      </ul>
                    )}
                  </div>
                </div>
              </div>
            ))}
          </div>
          <p className="mt-4 text-xs leading-relaxed text-zinc-500">Weights: standing privileged access +20 · unused 90d+ +15 (privileged) / +5 · SoD violation +25 · rogue account +35 (privileged) / +20 · unreviewed break-glass +15 · access outside role +4 · live JIT +5. Capped at 100; 25 / 50 / 75 mark medium / high / critical.</p>
        </Card>
      )}

      {tab === 'recon' && (
        <Card title="Target-system reconciliation" subtitle="Accounts found in applications, matched against the HR source and IAM grants" pad={false} delay={40}>
          <div className="overflow-x-auto">
            <table className="min-w-full">
              <thead><tr><th className="th ps-5">Account</th><th className="th">Finding</th><th className="th">Detail</th><th className="th">Last login</th><th className="th pe-5">Remediate</th></tr></thead>
              <tbody>
                {recon.accounts.map((a, i) => {
                  const m = findingMeta[a.finding]
                  const open = !['ok', 'disabled'].includes(a.finding)
                  return (
                    <tr key={a.id} className={`row animate-fade-in ${a.finding === 'disabled' ? 'opacity-50' : ''}`} style={{ animationDelay: `${i * 30}ms` }}>
                      <td className="td ps-5">
                        <div className="font-mono text-[13px] text-zinc-100">{a.accountName}</div>
                        <div className="text-xs text-zinc-500">{L.sys[a.systemId]?.name} · {a.type}{a.entitlementId && ` · ${L.entName(a.entitlementId)}`}</div>
                      </td>
                      <td className="td"><div className="flex flex-col items-start gap-1"><Badge tone={m.tone}><m.icon className="size-3" /> {m.label}</Badge>{open && <Badge tone={a.severity === 'critical' ? 'bad' : 'warn'}>{a.severity}</Badge>}</div></td>
                      <td className="td max-w-sm"><div className="text-zinc-300">{a.detail}</div>{a.note && <div className="mt-0.5 text-xs text-zinc-500">{a.note}</div>}</td>
                      <td className="td whitespace-nowrap text-xs text-zinc-400">{ago(a.lastLogin)}</td>
                      <td className="td pe-5">
                        {open ? (
                          <div className="flex flex-wrap gap-1.5">
                            <Button size="sm" variant="danger" onClick={() => act(a, 'disable')}><Power className="size-3.5" /> Disable</Button>
                            {a.finding === 'unowned-service' && <Button size="sm" variant="ghost" onClick={() => act(a, 'assign-owner')}><UserCheck className="size-3.5" /> Owner</Button>}
                            {a.finding === 'rogue' && <Button size="sm" variant="ghost" onClick={() => act(a, 'adopt')}><Link2 className="size-3.5" /> Adopt</Button>}
                          </div>
                        ) : <span className="text-xs text-zinc-600">—</span>}
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        </Card>
      )}

      {tab === 'dormant' && (
        <Card title="Dormant access" subtitle={`Grants not exercised in ${recon.dormantDays}+ days`} pad={false} delay={40}>
          {recon.dormant.length === 0 ? <Empty icon={CheckCircle2}>No dormant access.</Empty> : (
            <div className="overflow-x-auto">
              <table className="min-w-full">
                <thead><tr><th className="th ps-5">Person</th><th className="th">Entitlement</th><th className="th">Source</th><th className="th">Unused</th><th className="th pe-5" /></tr></thead>
                <tbody>
                  {recon.dormant.map((d) => (
                    <tr key={d.identityId + d.entitlementId} className="row">
                      <td className="td ps-5"><div className="flex items-center gap-2"><Avatar name={L.person(d.identityId)} size="size-7" /><span className="text-zinc-100">{L.person(d.identityId)}</span></div></td>
                      <td className="td"><div className="text-zinc-200">{L.entName(d.entitlementId)}</div><div className="text-xs text-zinc-500">{L.sysOf(d.entitlementId)}</div></td>
                      <td className="td"><div className="flex gap-1"><Badge tone="violet">{d.source}</Badge>{d.privileged && <Badge tone="bad">privileged</Badge>}</div></td>
                      <td className="td font-semibold tabular-nums text-amber-300">{d.daysUnused} days</td>
                      <td className="td pe-5 text-end"><Button size="sm" variant="danger" onClick={() => revokeDormant(d)}><Trash2 className="size-3.5" /> Revoke</Button></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
      )}
    </div>
  )
}
