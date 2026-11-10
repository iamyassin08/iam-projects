import { FlaskConical, CheckCircle2, XCircle, RefreshCw, Download } from 'lucide-react'
import { api } from '../api.js'
import { useLoad } from '../hooks.js'
import { PageHead, Badge, ErrorBox, Loading } from '../ui.jsx'

// Problem → Assumptions → Build → Test → Improve, one per module.
const MODULES = [
  {
    id: 'jml', title: 'JML workflow', href: '#jml',
    problem: 'People join, change jobs and leave every week. Access must follow them — on day one, on the day of a move, and on the last day.',
    assumptions: ['HR (Workday) is the source of truth for who works here and in what job.', 'Each job maps to exactly one role that defines birthright access.', 'A leaver must lose everything the same day.'],
    build: ['Joiner: create identity, grant role entitlements.', 'Mover: grant new-role access, revoke anything outside it — including request-based extras.', 'Leaver: disable, revoke all, cancel open requests.'],
    test: ['Onboard a joiner and confirm their grants equal the role.', 'Move Omar Farouk from Software Engineer to Revenue Cycle Analyst; confirm aws-dev and gh-member are gone.', 'Terminate someone; run checks C1 and C2.'],
    improve: ['Drive JML from HR events (webhook) instead of a form.', 'Add pre-hire accounts with a disabled-until-start-date flag.', 'Keep leaver mailboxes for 30 days under manager delegation.'],
    checks: ['C1', 'C2'],
  },
  {
    id: 'requests', title: 'Access request', href: '#requests',
    problem: 'Roles never cover everything. People need extra access, and someone accountable has to decide — with a record auditors can sample.',
    assumptions: ['Every request needs a business justification.', 'Approvers see SoD conflicts before they decide.', 'A conflict can be accepted only with a written reason.'],
    build: ['Request form with justification.', 'SoD check against the person\'s current grants at request time.', 'Approve → provision with source "request"; deny → nothing changes.'],
    test: ['Approve Priya\'s erp-approve request without a reason — it must be refused.', 'Approve it with a documented risk acceptance and run C4.', 'Request something a user already has — expect 409.'],
    improve: ['Route to the manager, then to the system owner (two-step approval).', 'Time-box privileged grants with automatic expiry.', 'Quarterly certification: managers keep or revoke each grant.'],
    checks: ['C3', 'C4'],
  },
  {
    id: 'roles', title: 'Role matrix', href: '#roles',
    problem: 'Roles drift. Someone adds "just one more" entitlement and suddenly every member has admin.',
    assumptions: ['Roles hold only what everyone in the job needs.', 'Privileged entitlements are never birthright.', 'A role must never contain both sides of an SoD rule.'],
    build: ['Roles × entitlements grid.', 'Toggling a cell re-syncs every active member.', 'Adding an entitlement that completes an SoD pair is blocked server-side.'],
    test: ['Add erp-vendor to AP Specialist — expect a block (sod-1).', 'Run C6: Finance Manager has erp-approve as birthright — a deliberate finding.', 'Remove it and re-run.'],
    improve: ['Role mining: suggest roles from what people actually hold.', 'Version roles and require approval for role changes.', 'Show blast radius before saving.'],
    checks: ['C5', 'C6'],
  },
  {
    id: 'systems', title: 'System map', href: '#systems',
    problem: 'You can\'t govern access to apps you don\'t know about, and you can\'t deprovision what isn\'t connected.',
    assumptions: ['Every app has a named owner.', 'Apps should federate through the IdP and be provisioned by SCIM or API.', 'Criticality drives review frequency.'],
    build: ['Inventory with protocol, provisioning, owner and criticality.', 'User and privileged-grant counts per system.', 'Flow from HR → IdP → directory → apps.'],
    test: ['Run C7: Epic EHR is provisioned manually — a deliberate finding.', 'Confirm user counts change after a leaver.'],
    improve: ['Discover shadow IT from SSO logs and expense reports.', 'Replace manual apps with SCIM connectors.', 'Track app-level review status.'],
    checks: ['C7'],
  },
]

function writeUp(checks) {
  const lines = ['# IAM Projects — lab write-up', '', `Generated ${new Date().toLocaleString()}`, '']
  const passed = checks.filter((c) => c.pass).length
  lines.push(`## Control checks: ${passed}/${checks.length} passing`, '')
  checks.forEach((c) => {
    lines.push(`- **${c.id} ${c.pass ? 'PASS' : 'FAIL'}** — ${c.control}`)
    c.findings.forEach((f) => lines.push(`  - ${f}`))
  })
  MODULES.forEach((m) => {
    lines.push('', `## ${m.title}`, '', `**Problem.** ${m.problem}`, '')
    ;[['Assumptions', m.assumptions], ['Build', m.build], ['Test', m.test], ['Improve', m.improve]].forEach(([h, items]) => {
      lines.push(`**${h}**`, ...items.map((x) => `- ${x}`), '')
    })
  })
  return lines.join('\n')
}

export default function Lab() {
  const [data, reload, error] = useLoad({ checks: api.checks })

  function download() {
    const blob = new Blob([writeUp(data.checks)], { type: 'text/markdown' })
    const url = URL.createObjectURL(blob)
    Object.assign(document.createElement('a'), { href: url, download: 'iam-lab-writeup.md' }).click()
    URL.revokeObjectURL(url)
  }

  if (!data) return <><ErrorBox error={error} /><Loading /></>
  const byId = Object.fromEntries(data.checks.map((c) => [c.id, c]))
  const passed = data.checks.filter((c) => c.pass).length

  return (
    <div>
      <PageHead icon={FlaskConical} title="Lab guide" job="Practice the lifecycle, not perfection">
        <button className="btn ghost" onClick={reload}><RefreshCw size={15} /> Re-run checks</button>
        <button className="btn primary" onClick={download}><Download size={15} /> Download write-up</button>
      </PageHead>
      <ErrorBox error={error} />

      <section className="panel">
        <div className="row-between">
          <h3>Live control checks</h3>
          <Badge kind={passed === data.checks.length ? 'ok' : 'warn'}>{passed}/{data.checks.length} passing</Badge>
        </div>
        <div className="checks">
          {data.checks.map((c) => (
            <div key={c.id} className={`check ${c.pass ? 'pass' : 'fail'}`}>
              {c.pass ? <CheckCircle2 size={18} /> : <XCircle size={18} />}
              <div>
                <strong>{c.id} · {c.control}</strong>
                <div className="muted small">{c.why}</div>
                {c.findings.map((f) => <div key={f} className="finding">{f}</div>)}
              </div>
            </div>
          ))}
        </div>
      </section>

      <section className="panel">
        <h3>Concepts</h3>
        <div className="visuals">
          <figure>
            <svg viewBox="0 0 320 150" className="viz">
              <rect x="8" y="30" width="130" height="80" rx="10" className="v-a" />
              <text x="73" y="62" textAnchor="middle" className="v-t">AuthN</text>
              <text x="73" y="84" textAnchor="middle" className="v-s">Who are you?</text>
              <rect x="182" y="30" width="130" height="80" rx="10" className="v-b" />
              <text x="247" y="62" textAnchor="middle" className="v-t">AuthZ</text>
              <text x="247" y="84" textAnchor="middle" className="v-s">What can you do?</text>
              <path d="M140 70 H178" className="v-line" markerEnd="url(#arr)" />
              <defs><marker id="arr" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto"><path d="M0 0 L10 5 L0 10 z" className="v-head" /></marker></defs>
              <text x="160" y="138" textAnchor="middle" className="v-s">SAML / OIDC / MFA  →  roles, entitlements, policies</text>
            </svg>
            <figcaption>Authentication proves identity; authorization decides access. This lab is mostly AuthZ.</figcaption>
          </figure>
          <figure>
            <svg viewBox="0 0 320 150" className="viz">
              {[['Identity', 20], ['Role', 120], ['Entitlement', 220]].map(([t, x]) => (
                <g key={t}><rect x={x} y="45" width="84" height="44" rx="8" className="v-a" /><text x={x + 42} y="72" textAnchor="middle" className="v-t sm">{t}</text></g>
              ))}
              <path d="M104 67 H118" className="v-line" /><path d="M204 67 H218" className="v-line" />
              <text x="160" y="118" textAnchor="middle" className="v-s">binding = who + what + where</text>
              <text x="160" y="136" textAnchor="middle" className="v-s">grant source: role (birthright) or request</text>
            </svg>
            <figcaption>Policy binding: an identity gets entitlements through a role or an approved request.</figcaption>
          </figure>
          <figure>
            <svg viewBox="0 0 320 150" className="viz">
              <rect x="110" y="8" width="100" height="30" rx="6" className="v-b" /><text x="160" y="28" textAnchor="middle" className="v-t sm">Organization</text>
              <rect x="40" y="58" width="100" height="30" rx="6" className="v-a" /><text x="90" y="78" textAnchor="middle" className="v-t sm">System</text>
              <rect x="180" y="58" width="100" height="30" rx="6" className="v-a" /><text x="230" y="78" textAnchor="middle" className="v-t sm">System</text>
              <rect x="10" y="108" width="80" height="28" rx="6" className="v-c" /><text x="50" y="127" textAnchor="middle" className="v-s">Entitlement</text>
              <rect x="100" y="108" width="80" height="28" rx="6" className="v-c" /><text x="140" y="127" textAnchor="middle" className="v-s">Entitlement</text>
              <rect x="210" y="108" width="80" height="28" rx="6" className="v-c" /><text x="250" y="127" textAnchor="middle" className="v-s">Entitlement</text>
              <path d="M160 38 L90 58 M160 38 L230 58 M90 88 L50 108 M90 88 L140 108 M230 88 L250 108" className="v-line" />
            </svg>
            <figcaption>Resource hierarchy: permissions live on resources inside systems inside the org.</figcaption>
          </figure>
        </div>
      </section>

      {MODULES.map((m) => (
        <section className="panel lab-mod" key={m.id}>
          <div className="row-between">
            <h3>{m.title}</h3>
            <div className="chips">
              {m.checks.map((id) => byId[id] && <Badge key={id} kind={byId[id].pass ? 'ok' : 'bad'}>{id} {byId[id].pass ? 'pass' : 'fail'}</Badge>)}
              <a className="btn small ghost" href={m.href}>Open module</a>
            </div>
          </div>
          <p><strong>Problem.</strong> {m.problem}</p>
          <div className="steps">
            {[['Assumptions', m.assumptions], ['Build', m.build], ['Test', m.test], ['Improve', m.improve]].map(([h, items]) => (
              <div key={h} className="step"><div className="eyebrow">{h}</div><ul>{items.map((x) => <li key={x}>{x}</li>)}</ul></div>
            ))}
          </div>
        </section>
      ))}
    </div>
  )
}
