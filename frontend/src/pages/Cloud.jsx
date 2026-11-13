import { useEffect, useState } from 'react'
import { Cloud as CloudIcon, Save, Play, AlertTriangle, CheckCircle2, XCircle, Wand2, FolderTree, Timer } from 'lucide-react'
import { api } from '../api.js'
import { useLoad, PageHeader, Card, Badge, Button, ErrorBox, Loading, Seg, toast, Field, Stat, usePreline, levelTone } from '../ui.jsx'

const FIXES = {
  'pol-legacy': `{
  "Version": "2012-10-17",
  "Statement": [
    { "Sid": "DeployArtifacts", "Effect": "Allow", "Action": ["s3:PutObject", "s3:GetObject"], "Resource": "arn:aws:s3:::acme-deploy-artifacts/*" },
    { "Sid": "UpdateLambda", "Effect": "Allow", "Action": ["lambda:UpdateFunctionCode", "lambda:PublishVersion"], "Resource": "arn:aws:lambda:us-east-1:111122223333:function:app-*" }
  ]
}`,
  'pol-iam': `{
  "Version": "2012-10-17",
  "Statement": [
    { "Sid": "ManageUsersWithMFA", "Effect": "Allow",
      "Action": ["iam:CreateUser", "iam:DeleteUser", "iam:AttachUserPolicy", "iam:CreateAccessKey", "iam:DeleteAccessKey", "iam:List*", "iam:Get*"],
      "Resource": "arn:aws:iam::111122223333:user/*",
      "Condition": { "Bool": { "aws:MultiFactorAuthPresent": "true" } } },
    { "Sid": "PassOnlyAppRoles", "Effect": "Allow", "Action": "iam:PassRole", "Resource": "arn:aws:iam::111122223333:role/app-*",
      "Condition": { "Bool": { "aws:MultiFactorAuthPresent": "true" } } }
  ]
}`,
}

const SCENARIOS = [
  { label: 'Dev deploys a dev Lambda', principal: 'user/omar.farouk', action: 'lambda:UpdateFunctionCode', resource: 'arn:aws:lambda:us-east-1:111122223333:function:dev-api' },
  { label: 'Dev touches a prod Lambda', principal: 'user/omar.farouk', action: 'lambda:UpdateFunctionCode', resource: 'arn:aws:lambda:us-east-1:111122223333:function:prod-api' },
  { label: 'Dev reads prod data', principal: 'user/omar.farouk', action: 's3:GetObject', resource: 'arn:aws:s3:::acme-prod-claims/2026/q3.csv' },
  { label: 'Dev launches EC2 (boundary)', principal: 'user/omar.farouk', action: 'ec2:RunInstances', resource: '*' },
  { label: 'Analyst reads claims', principal: 'role/DataAnalyst', action: 's3:GetObject', resource: 'arn:aws:s3:::acme-rcm-extracts/claims/q3.csv' },
  { label: 'IAM engineer creates a key', principal: 'role/IAMEngineer', action: 'iam:CreateAccessKey', resource: 'arn:aws:iam::111122223333:user/omar.farouk' },
  { label: 'Legacy CI user deletes a trail', principal: 'user/svc-legacy-deploy', action: 'cloudtrail:DeleteTrail', resource: 'arn:aws:cloudtrail:us-east-1:111122223333:trail/org' },
]

const decisionTone = { allowed: 'ok', 'explicit-deny': 'bad', 'implicit-deny': 'warn', 'boundary-deny': 'warn' }

const TREE = [
  { id: 'mg-acme-root', label: 'Management group: mg-acme-root', depth: 0 },
  { id: 'sub-acme-prod', label: 'Subscription: sub-acme-prod', depth: 1 },
  { id: 'rg-app-prod', label: 'Resource group: rg-app-prod', depth: 2 },
  { id: 'rg-rcm-data', label: 'Resource group: rg-rcm-data', depth: 2 },
  { id: 'sub-acme-dev', label: 'Subscription: sub-acme-dev', depth: 1 },
  { id: 'rg-app-dev', label: 'Resource group: rg-app-dev', depth: 2 },
]

export default function Cloud() {
  const [data, reload, error] = useLoad({ cloud: api.cloud })
  const [tab, setTab] = useState('policies')
  const [pid, setPid] = useState('pol-legacy')
  const [doc, setDoc] = useState('')
  const [sim, setSim] = useState({ ...SCENARIOS[0], context: { mfa: true, sourceIp: '198.51.100.18', region: 'us-east-1' } })
  const [res, setRes] = useState(null)
  usePreline([data, tab])

  const pol = data?.cloud.policies.find((p) => p.id === pid)
  useEffect(() => { if (pol) setDoc(pol.document) }, [pid, data]) // eslint-disable-line react-hooks/exhaustive-deps

  async function save() {
    try { const r = await api.savePolicy(pid, doc, ''); await reload(); toast(`Saved. ${r.findings.length} finding(s) remain.`, r.findings.length ? 'warn' : 'ok') } catch (e) { toast(e.message, 'err') }
  }
  async function run(s = sim) {
    try { setRes(await api.simulate(s)) } catch (e) { toast(e.message, 'err') }
  }
  async function makeEligible(a) {
    try { await api.makeEligible(a.id); await reload(); toast('Now PIM-eligible: no standing access') } catch (e) { toast(e.message, 'err') }
  }

  if (!data) return <><ErrorBox error={error} /><Loading /></>
  const { cloud } = data
  const fFor = (id) => cloud.findings.filter((f) => f.policyId === id)
  const crit = cloud.findings.filter((f) => f.severity === 'critical' || f.severity === 'high').length

  return (
    <div className="space-y-6">
      <PageHeader icon={CloudIcon} eyebrow="Project 7 · cloud IAM, least privilege · NIST AC-6, CIS 6.8" title="Cloud IAM policies"
        desc="AWS identity policies, a permissions boundary, and Azure RBAC role assignments for the demo company. The policy engine follows AWS evaluation logic: an explicit Deny always wins, otherwise an Allow is required, and a permissions boundary caps what any policy can grant. A linter flags the misconfigurations attackers look for. Fix a policy and re-test it in the simulator." />
      <ErrorBox error={error} />

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <Stat label="AWS policies" value={cloud.policies.length} icon={CloudIcon} />
        <Stat label="High / critical findings" value={crit} icon={AlertTriangle} tone={crit ? 'bad' : 'ok'} delay={60} />
        <Stat label="Azure role assignments" value={cloud.azure.length} icon={FolderTree} tone="info" delay={120} />
        <Stat label="Azure findings" value={cloud.azureFindings.length} icon={Timer} tone={cloud.azureFindings.length ? 'warn' : 'ok'} delay={180} />
      </div>

      <Seg value={tab} onChange={setTab} options={[{ value: 'policies', label: 'AWS policies' }, { value: 'sim', label: 'Policy simulator' }, { value: 'azure', label: 'Azure RBAC' }]} />

      {tab === 'policies' && (
        <div className="grid gap-6 lg:grid-cols-5">
          <Card className="lg:col-span-2" title="Policies" subtitle="Click one to review and edit" pad={false}>
            <ul className="divide-y divide-white/[0.06]">
              {cloud.policies.map((p) => {
                const f = fFor(p.id)
                return (
                  <li key={p.id}>
                    <button type="button" onClick={() => setPid(p.id)} className={`w-full px-5 py-3 text-start transition ${pid === p.id ? 'bg-white/[0.05]' : 'hover:bg-white/[0.025]'}`}>
                      <div className="flex items-center justify-between gap-2">
                        <span className="font-medium text-zinc-100">{p.name}</span>
                        {f.length ? <Badge tone={f.some((x) => x.severity === 'critical') ? 'bad' : 'warn'}>{f.length} finding{f.length > 1 ? 's' : ''}</Badge> : <Badge tone="ok"><CheckCircle2 className="size-3" /> clean</Badge>}
                      </div>
                      <div className="mt-0.5 text-xs text-zinc-500">{p.attachedTo.length ? `attached to ${p.attachedTo.join(', ')}` : 'permissions boundary'}</div>
                    </button>
                  </li>
                )
              })}
            </ul>
            <div className="border-t border-white/[0.06] px-5 py-3 text-xs text-zinc-500">
              Principals: {cloud.principals.map((p) => <span key={p.id} className="me-2 inline-block"><span className="code">{p.id}</span>{p.boundary ? ' (boundary)' : ''}</span>)}
            </div>
          </Card>
          <Card className="lg:col-span-3" title={pol?.name} subtitle={pol?.description}
            actions={<>{FIXES[pid] && <Button size="sm" variant="ghost" onClick={() => setDoc(FIXES[pid])}><Wand2 className="size-3.5" /> Load least-privilege fix</Button>}<Button size="sm" onClick={save}><Save className="size-3.5" /> Save & re-lint</Button></>}>
            <textarea className="input min-h-72 font-mono text-[12px] leading-relaxed" spellCheck={false} value={doc} onChange={(e) => setDoc(e.target.value)} aria-label="Policy JSON" />
            <div className="mt-4 space-y-2">
              {fFor(pid).length === 0 && <p className="flex items-center gap-2 text-sm text-emerald-300"><CheckCircle2 className="size-4" /> No findings: scoped actions, scoped resources, MFA on sensitive actions.</p>}
              {fFor(pid).map((f, i) => (
                <div key={i} className="rounded-xl border border-white/[0.07] bg-white/[0.02] p-3 text-sm">
                  <div className="flex flex-wrap items-center gap-2"><Badge tone={levelTone[f.severity]}>{f.severity}</Badge><span className="font-mono text-xs text-zinc-500">{f.sid} · {f.rule}</span></div>
                  <div className="mt-1 text-zinc-200">{f.detail}</div>
                  <div className="mt-1 text-xs text-emerald-300/90">Fix: {f.fix}</div>
                </div>
              ))}
            </div>
          </Card>
        </div>
      )}

      {tab === 'sim' && (
        <div className="grid gap-6 lg:grid-cols-5">
          <Card className="lg:col-span-2" title="Request" subtitle="Who wants to do what, to which resource">
            <div className="mb-4 flex flex-wrap gap-1.5">
              {SCENARIOS.map((s) => <button key={s.label} type="button" onClick={() => { const n = { ...sim, ...s }; setSim(n); run(n) }} className="rounded-full px-2.5 py-1 text-[11px] text-zinc-300 ring-1 ring-inset ring-white/10 hover:bg-white/5">{s.label}</button>)}
            </div>
            <div className="space-y-3">
              <Field label="Principal"><select className="input" value={sim.principal} onChange={(e) => setSim({ ...sim, principal: e.target.value })}>{cloud.principals.map((p) => <option key={p.id} value={p.id}>{p.id}</option>)}</select></Field>
              <Field label="Action"><input className="input font-mono text-xs" value={sim.action} onChange={(e) => setSim({ ...sim, action: e.target.value })} /></Field>
              <Field label="Resource ARN"><input className="input font-mono text-xs" value={sim.resource} onChange={(e) => setSim({ ...sim, resource: e.target.value })} /></Field>
              <div className="grid grid-cols-3 gap-2">
                <Field label="MFA"><Seg value={String(sim.context.mfa)} onChange={(v) => setSim({ ...sim, context: { ...sim.context, mfa: v === 'true' } })} options={[{ value: 'true', label: 'Yes' }, { value: 'false', label: 'No' }]} /></Field>
                <Field label="Source IP"><select className="input text-xs" value={sim.context.sourceIp} onChange={(e) => setSim({ ...sim, context: { ...sim.context, sourceIp: e.target.value } })}><option value="198.51.100.18">Office 198.51.100.18</option><option value="192.0.2.77">Lagos 192.0.2.77</option></select></Field>
                <Field label="Region"><select className="input text-xs" value={sim.context.region} onChange={(e) => setSim({ ...sim, context: { ...sim.context, region: e.target.value } })}><option>us-east-1</option><option>eu-west-1</option></select></Field>
              </div>
              <Button className="w-full" onClick={() => run()}><Play className="size-4" /> Evaluate</Button>
            </div>
          </Card>
          <Card className="lg:col-span-3" title="Decision" subtitle="Every statement the engine looked at, in order">
            {!res ? <p className="text-sm text-zinc-500">Pick a scenario or press Evaluate.</p> : (
              <div className="space-y-3 animate-fade-in">
                <div className={`flex items-center gap-3 rounded-xl border p-3 ${res.decision === 'allowed' ? 'border-emerald-500/30 bg-emerald-500/10' : 'border-rose-500/30 bg-rose-500/10'}`}>
                  {res.decision === 'allowed' ? <CheckCircle2 className="size-5 text-emerald-300" /> : <XCircle className="size-5 text-rose-300" />}
                  <div><Badge tone={decisionTone[res.decision]}>{res.decision}</Badge><div className="mt-1 text-sm text-zinc-200">{res.reason}</div></div>
                </div>
                <table className="min-w-full text-sm">
                  <thead><tr><th className="th">Policy</th><th className="th">Statement</th><th className="th">Effect</th><th className="th">Result</th></tr></thead>
                  <tbody>
                    {res.trace.map((t, i) => (
                      <tr key={i} className="row">
                        <td className="td text-xs text-zinc-300">{t.policy}{t.layer === 'boundary' && <Badge tone="info" className="ms-1">boundary</Badge>}</td>
                        <td className="td font-mono text-xs text-zinc-400">{t.sid}</td>
                        <td className="td"><Badge tone={t.effect === 'Deny' ? 'bad' : 'ok'}>{t.effect}</Badge></td>
                        <td className="td text-xs">{t.matched ? <span className="text-violet-200">✓ {t.why}</span> : <span className="text-zinc-500">✗ {t.why}</span>}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                <div className="rounded-xl border border-white/[0.07] p-3 text-xs leading-relaxed text-zinc-400">
                  <b className="text-zinc-200">Evaluation order:</b> explicit Deny in any policy → deny. Otherwise, no matching Allow → implicit deny. Otherwise, if a permissions boundary exists it must also Allow. Same logic as the AWS IAM policy simulator, minus SCPs and resource policies.
                </div>
              </div>
            )}
          </Card>
        </div>
      )}

      {tab === 'azure' && (
        <div className="grid gap-6 lg:grid-cols-5">
          <Card className="lg:col-span-3" title="Scope hierarchy" subtitle="Assignments inherit downward: Owner on a subscription is Owner on everything in it">
            <ul className="space-y-2">
              {TREE.map((n) => {
                const as = cloud.azure.filter((a) => a.scope === n.id)
                return (
                  <li key={n.id} style={{ marginInlineStart: `${n.depth * 24}px` }} className="rounded-xl border border-white/[0.07] bg-white/[0.02] p-3">
                    <div className="flex items-center gap-2 text-sm font-medium text-zinc-200"><FolderTree className="size-4 text-sky-300" />{n.label}</div>
                    {as.length > 0 && <ul className="mt-2 space-y-1.5">
                      {as.map((a) => {
                        const bad = cloud.azureFindings.some((f) => f.assignmentId === a.id && f.severity === 'high')
                        return (
                          <li key={a.id} className={`flex flex-wrap items-center gap-2 rounded-lg px-2.5 py-1.5 text-xs ${bad ? 'bg-rose-500/10 ring-1 ring-rose-500/30' : 'bg-zinc-950/50'}`}>
                            <span className="text-zinc-200">{a.principal}</span><span className="text-zinc-500">({a.kind})</span>
                            <Badge tone={a.role === 'Owner' || a.role === 'User Access Administrator' ? 'bad' : 'violet'}>{a.role}</Badge>
                            <Badge tone={a.type === 'eligible' ? 'ok' : 'warn'}>{a.type === 'eligible' ? 'PIM eligible' : 'permanent'}</Badge>
                            {bad && <Button size="sm" variant="ghost" className="ms-auto" onClick={() => makeEligible(a)}>Make PIM-eligible</Button>}
                          </li>
                        )
                      })}
                    </ul>}
                  </li>
                )
              })}
            </ul>
          </Card>
          <Card className="lg:col-span-2" title="Findings" subtitle="Standing privileged access at broad scope">
            {cloud.azureFindings.length === 0 ? <p className="flex items-center gap-2 text-sm text-emerald-300"><CheckCircle2 className="size-4" /> No standing Owner / UAA at subscription scope.</p> : (
              <ul className="space-y-2">{cloud.azureFindings.map((f, i) => (
                <li key={i} className="rounded-xl border border-white/[0.07] p-3 text-sm"><Badge tone={levelTone[f.severity]}>{f.severity}</Badge><div className="mt-1 text-zinc-200">{f.detail}</div><div className="mt-1 text-xs text-emerald-300/90">Fix: {f.fix}</div></li>
              ))}</ul>
            )}
            <p className="mt-4 text-xs leading-relaxed text-zinc-500">In a real tenant: Entra ID → Privileged Identity Management → Azure resources → Roles → convert the assignment from Active to Eligible, with MFA and justification on activation and a maximum duration.</p>
          </Card>
        </div>
      )}
    </div>
  )
}
