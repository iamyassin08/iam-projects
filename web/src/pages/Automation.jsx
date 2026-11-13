import { useEffect, useState } from 'react'
import { Terminal, Eye, Play, FileSpreadsheet, AlertTriangle, RotateCcw } from 'lucide-react'
import { api } from '../api.js'
import { PageHeader, Card, Badge, Button, toast, ask, Seg } from '../ui.jsx'
import { CodeBlock, Flow } from '../components.jsx'
import py from '../../../scripts/iamctl.py?raw'
import ps from '../../../scripts/IamCtl.ps1?raw'

const tone = { joiner: 'ok', mover: 'info', update: 'violet', leaver: 'bad', noop: 'neutral', skip: 'warn', error: 'bad' }

const SAMPLE_RUN = `$ export IAM_BASE_URL=https://iam.assafwahinc.com IAM_SCIM_TOKEN=scim_…
$ python3 iamctl.py sync hr_feed_sample.csv
ACTION   EMPLOYEE   NAME                   DETAIL
noop     WD-10040   Omar Farouk            in sync
mover    WD-10057   Daniel Brooks          role r-sales -> r-eng; title -> Solutions Engineer; department -> Engineering
leaver   WD-10108   Marcus Lee             deactivate and revoke all access
update   WD-10125   Sofia Alvarez          title -> Senior Service Desk Analyst
joiner   WD-10300   Amina Yusuf            create with role r-ap
skip     WD-10301   Tom Becker             terminated in HR, never provisioned

DRY RUN (add --apply to make changes): joiner=1, leaver=1, mover=1, noop=4, skip=1, update=1

$ python3 iamctl.py sync hr_feed_sample.csv --apply     # second run: noop=8, skip=1 (idempotent)
$ python3 iamctl.py dormant --days 90
 210d  Sofia Alvarez      Active Directory         Domain Admins  [PRIVILEGED]
$ python3 iamctl.py report --out access.csv
wrote 33 grants for 7 people to access.csv (4 flagged)`

export default function Automation() {
  const [csv, setCsv] = useState('')
  const [res, setRes] = useState(null)
  const [busy, setBusy] = useState(false)
  const [lang, setLang] = useState('py')

  const loadSample = () => api.hrSample().then(setCsv)
  useEffect(() => { loadSample() }, [])

  async function run(apply) {
    if (apply) {
      const ok = await ask({ title: 'Apply the HR feed?', message: 'Joiners are created, movers change role (old access revoked), leavers are terminated, and every change is audited as "via hr-feed". Reset the demo from Security posture to undo.', input: false, confirm: 'Apply changes' })
      if (!ok) return
    }
    setBusy(true)
    try { const r = await api.hrFeed(csv, apply); setRes(r); toast(apply ? 'Feed applied' : 'Dry run complete', apply ? 'ok' : 'info') } catch (e) { toast(e.message, 'err') }
    setBusy(false)
  }
  const counts = res ? res.plan.reduce((m, a) => ({ ...m, [a.action]: (m[a.action] || 0) + 1 }), {}) : {}

  return (
    <div className="space-y-6">
      <PageHeader icon={Terminal} eyebrow="Project 10 · IAM automation · Python, PowerShell, SCIM, REST" title="Automation"
        desc="An HR system exports a CSV every night; IAM turns it into joiner, mover and leaver actions. Here that runs in the browser against the same lifecycle code the UI and SCIM use, with a dry run first. The same job ships as iamctl.py (Python standard library only) driving the public SCIM 2.0 API, plus an access report, a dormant-access finder and a PowerShell companion." />

      <Card title="Pipeline">
        <Flow nodes={[
          { title: 'HR export (CSV)', sub: 'employee_id, role_id, status…' },
          { title: 'Match', sub: 'by employee ID, then email' },
          { title: 'Plan (dry run)', sub: 'joiner · mover · update · leaver · skip', tone: 'amber' },
          { title: 'Apply via SCIM', sub: 'POST /Users · PATCH active · PATCH Groups' },
          { title: 'Audit + report', sub: 'every change attributed; CSV report', tone: 'emerald' },
        ]} />
      </Card>

      <div className="grid gap-6 lg:grid-cols-2">
        <Card title="HR feed" subtitle="Edit freely: change a role_id to make a mover, set status=terminated for a leaver"
          actions={<Button size="sm" variant="subtle" onClick={loadSample}><RotateCcw className="size-3.5" /> Sample</Button>}>
          <textarea className="input min-h-72 font-mono text-[11px] leading-relaxed" spellCheck={false} value={csv} onChange={(e) => setCsv(e.target.value)} aria-label="HR feed CSV" />
          <div className="mt-3 flex gap-2">
            <Button variant="ghost" onClick={() => run(false)} disabled={busy}><Eye className="size-4" /> Dry run</Button>
            <Button onClick={() => run(true)} disabled={busy || !res}><Play className="size-4" /> Apply</Button>
          </div>
        </Card>
        <Card title={res?.applied ? 'Applied' : 'Plan'} subtitle={res ? Object.entries(counts).map(([k, v]) => `${k} ${v}`).join(' · ') : 'Run a dry run to see what would change'} pad={false}>
          {!res ? <div className="grid place-items-center gap-2 py-16 text-sm text-zinc-500"><FileSpreadsheet className="size-8 text-zinc-600" />Nothing changes until you press Apply.</div> : (
            <div className="max-h-96 overflow-auto">
              <table className="min-w-full text-xs">
                <thead className="sticky top-0 bg-zinc-900"><tr><th className="th">Row</th><th className="th">Action</th><th className="th">Employee</th><th className="th">Detail</th></tr></thead>
                <tbody>{res.plan.map((a) => (
                  <tr key={a.row} className="row">
                    <td className="td text-zinc-500">{a.row}</td>
                    <td className="td"><Badge tone={tone[a.action]}>{a.action}</Badge></td>
                    <td className="td"><div className="text-zinc-200">{a.name}</div><div className="font-mono text-[10px] text-zinc-500">{a.employeeId}</div></td>
                    <td className="td text-zinc-400">{a.detail}{a.changes.length > 0 && <ul className="mt-1 space-y-0.5 text-zinc-300">{a.changes.map((c) => <li key={c}>• {c}</li>)}</ul>}</td>
                  </tr>
                ))}</tbody>
              </table>
              {res.warnings.length > 0 && <div className="space-y-1 border-t border-white/[0.06] p-4">{res.warnings.map((w) => <div key={w} className="flex gap-2 text-xs text-amber-300"><AlertTriangle className="mt-0.5 size-3.5 shrink-0" />{w}</div>)}</div>}
            </div>
          )}
        </Card>
      </div>

      <Card title="The scripts" subtitle="scripts/ in the repo · no dependencies to install" actions={<Seg value={lang} onChange={setLang} options={[{ value: 'py', label: 'iamctl.py' }, { value: 'ps', label: 'IamCtl.ps1' }, { value: 'run', label: 'Example run' }]} />}>
        {lang === 'py' && <CodeBlock lang="python" maxH="max-h-[520px]">{py}</CodeBlock>}
        {lang === 'ps' && <CodeBlock lang="powershell" maxH="max-h-[520px]">{ps}</CodeBlock>}
        {lang === 'run' && <CodeBlock lang="terminal">{SAMPLE_RUN}</CodeBlock>}
        <div className="mt-4 grid gap-3 text-xs text-zinc-400 md:grid-cols-3">
          <div className="rounded-xl border border-white/[0.07] p-3"><b className="text-zinc-200">Safe by default.</b> sync is a dry run unless you pass --apply, and people missing from the feed are flagged, never auto-terminated.</div>
          <div className="rounded-xl border border-white/[0.07] p-3"><b className="text-zinc-200">Idempotent.</b> Running the same feed twice makes no further changes, so it can run nightly from cron or a pipeline.</div>
          <div className="rounded-xl border border-white/[0.07] p-3"><b className="text-zinc-200">Least privilege.</b> Provisioning uses a SCIM bearer token (hashed at rest, rotation checked by C14); reporting is read-only.</div>
        </div>
      </Card>
    </div>
  )
}
