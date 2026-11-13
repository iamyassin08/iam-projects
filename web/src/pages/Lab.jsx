import { useState } from 'react'
import { FlaskConical, CheckCircle2, XCircle, RefreshCw, Download, ChevronDown, ArrowRight } from 'lucide-react'
import { api, downloadFile } from '../api.js'
import { useLoad, PageHeader, Card, Badge, Button, ErrorBox, Loading, Ring, Seg, usePreline, Tooltip, toast } from '../ui.jsx'

// Problem → Assumptions → Build → Test → Improve, one per module.
const MODULES = [
  {
    id: 'jml', title: 'Identity lifecycle (JML)', checks: ['C1', 'C2'],
    problem: 'People join, change jobs and leave every week. Access must follow them on day one, on the day of a move, and on the last day.',
    assumptions: ['HR is authoritative for who works here and in what job.', 'One job maps to one role that defines birthright access.', 'A leaver loses everything the same day.'],
    build: ['Joiner: create identity, grant role entitlements.', 'Mover: grant new-role access and revoke anything outside it, including request-based extras.', 'Leaver: disable, revoke all, end JIT sessions, cancel open requests.'],
    test: ['Move Omar Farouk to Revenue Cycle Analyst; confirm aws-dev, gh-member and his gh-owner exception are gone.', 'Terminate Marcus Lee and watch reconciliation flag his Epic account (manual system).', 'Run C1 and C2.'],
    improve: ['Drive JML from HR webhooks.', 'Pre-hire accounts disabled until start date.', 'Mailbox retention with manager delegation for leavers.'],
  },
  {
    id: 'scim', title: 'SCIM 2.0 provisioning', checks: ['C14', 'C1'],
    problem: 'The IdP, not a person, should create and remove accounts. Every app that cannot accept SCIM becomes a manual ticket.',
    assumptions: ['Users map to identities and Groups map to roles.', 'The IdP authenticates with a long random bearer token.', 'IdPs differ: Entra ID sends "Replace" and "False" as strings.'],
    build: ['RFC 7644 /Users and /Groups with filter (eq, ne, co, sw, ew, pr, and) and paging.', 'PATCH active=false triggers the leaver flow; group add triggers the mover flow.', 'Tokens hashed with SHA-256 and compared in constant time; errors use the SCIM error schema.'],
    test: ['Generate a token, POST a user with groups, and confirm birthright grants.', 'PATCH active "False" Entra-style; confirm C1 still passes.', 'Revoke the token; the next call returns 401.'],
    improve: ['OAuth 2.0 client credentials instead of static tokens.', 'ETags and If-Match for concurrency.', 'Bulk endpoint for initial loads.'],
  },
  {
    id: 'requests', title: 'Access requests & SoD', checks: ['C3', 'C4'],
    problem: 'Roles never cover everything. Extra access needs an accountable decision and a record an auditor can sample.',
    assumptions: ['Every request has a justification.', 'Approvers see SoD conflicts before deciding.', 'A conflict is approved only with a written risk acceptance.'],
    build: ['Request form with SoD evaluation at request time.', 'Approve provisions with source "request"; deny changes nothing.', 'Duplicate and already-held requests are refused (409).'],
    test: ['Approve Priya Raman\'s Payment Approver request without a reason: refused (sod-2).', 'Approve it with a risk acceptance and run C4.'],
    improve: ['Manager → owner approval chains.', 'Expiry dates on approved exceptions.'],
  },
  {
    id: 'certifications', title: 'Access reviews', checks: ['C13'],
    problem: 'Access accumulates. Auditors expect every in-scope grant to be re-justified periodically by someone accountable.',
    assumptions: ['The manager is the reviewer.', 'Revocations must actually remove access.', 'Silence is not approval.'],
    build: ['Campaigns snapshot grants by scope (all, privileged, exceptions, one app).', 'Revoking birthright records an exclusion so role re-syncs respect it.', 'Close with revoke-on-non-response; export CSV evidence.'],
    test: ['Decide the Q4 privileged review; note Sofia\'s Domain Admin unused for 200+ days.', 'Close a campaign with undecided items and confirm they are revoked.'],
    improve: ['Multi-level reviews (manager then app owner).', 'Delegation and reminders.', 'Micro-certifications triggered by risk.'],
  },
  {
    id: 'pam', title: 'Just-in-time privileged access', checks: ['C8', 'C9', 'C6'],
    problem: 'Standing admin rights are the most valuable thing an attacker can steal. Most of the time nobody needs them.',
    assumptions: ['Admins are eligible, not assigned.', 'Every activation has a ticket and a time limit.', 'Emergencies happen, so break-glass exists and is reviewed.'],
    build: ['Eligibility with per-assignment max duration.', 'Elevation creates a JIT grant with expiresAt; a goroutine sweeps expired grants every 15s.', 'Break-glass capped at 60 minutes and flagged until reviewed; elevations that would break SoD are refused.'],
    test: ['Activate Yusuf\'s ServiceNow admin for 5 minutes; watch it expire.', 'Try Omar\'s AWS admin: refused, because aws-dev + aws-admin breaks sod-3.', 'Review the seeded break-glass session; C9 passes.'],
    improve: ['Approval workflow for high-risk roles.', 'Session recording.', 'Credential vaulting and rotation.'],
  },
  {
    id: 'roles', title: 'Role engineering', checks: ['C5', 'C6'],
    problem: 'Roles drift. Someone adds "just one more" entitlement and every member gets admin.',
    assumptions: ['A role holds only what everyone in the job needs.', 'Privileged entitlements are never birthright.', 'A role cannot contain both sides of an SoD rule.'],
    build: ['Roles × entitlements grid with immediate member re-sync.', 'Server-side block on SoD-completing changes.'],
    test: ['Add Vendor Master to AP Specialist: blocked by sod-1.', 'Remove Payment Approver from Finance Manager to clear C6, then give Grace JIT eligibility instead.'],
    improve: ['Role mining from actual grants.', 'Versioned roles with approval.'],
  },
  {
    id: 'risk', title: 'Risk & reconciliation', checks: ['C10', 'C11', 'C12'],
    problem: 'IAM only knows what it granted. Accounts created directly in apps, and accounts that deprovisioning missed, are invisible without reconciliation.',
    assumptions: ['Target systems can be read even if not written.', 'Every account maps to an identity, or to an owner if it is a service account.', 'Unused privilege is risk without benefit.'],
    build: ['Classify target accounts as orphan, rogue or unowned-service, with severity.', 'Remediate by disable, assign owner, or adopt (adoption is refused if it would legitimise an SoD violation).', 'Explainable additive risk score per identity.'],
    test: ['Disable mlee.clinical (rogue Epic access that breaks sod-4); Marcus\'s score drops.', 'Assign an owner to svc-legacy-deploy.', 'Revoke Sofia\'s dormant Domain Admin; C12 passes.'],
    improve: ['Real connectors per system.', 'Peer-group outlier analysis.', 'Feed risk into access reviews.'],
  },
  {
    id: 'systems', title: 'Application inventory', checks: ['C7'],
    problem: 'You can\'t govern apps you don\'t know about, and you can\'t deprovision what isn\'t connected.',
    assumptions: ['Every app has a named owner.', 'Apps federate through the IdP and provision by SCIM or API.'],
    build: ['Inventory with protocol, provisioning method, owner and criticality.', 'Identity flow from HR to cloud.'],
    test: ['C7 flags Epic EHR as manually provisioned, a deliberate finding.'],
    improve: ['Shadow IT discovery from SSO and expense data.', 'Replace manual apps with SCIM connectors.'],
  },
]

function writeUp(checks) {
  const passed = checks.filter((c) => c.pass).length
  const lines = ['# IAM Projects: lab write-up', '', `Generated ${new Date().toLocaleString()} from the live tenant.`, '', `## Control posture: ${passed}/${checks.length} passing`, '',
    '| ID | Control | Result | Frameworks |', '|---|---|---|---|',
    ...checks.map((c) => `| ${c.id} | ${c.control} | ${c.pass ? 'PASS' : 'FAIL'} | ${c.frameworks.join('; ')} |`), '']
  const failing = checks.filter((c) => !c.pass)
  if (failing.length) {
    lines.push('### Findings', '')
    failing.forEach((c) => { lines.push(`**${c.id} ${c.control}**`); c.findings.forEach((f) => lines.push(`- ${f}`)); lines.push('') })
  }
  MODULES.forEach((m) => {
    lines.push(`## ${m.title}`, '', `**Problem.** ${m.problem}`, '')
    ;[['Assumptions', m.assumptions], ['Build', m.build], ['Test', m.test], ['Improve', m.improve]].forEach(([h, xs]) => lines.push(`**${h}**`, ...xs.map((x) => `- ${x}`), ''))
  })
  return lines.join('\n')
}

export default function Lab() {
  const [data, reload, error] = useLoad({ checks: api.checks })
  const [filter, setFilter] = useState('all')
  usePreline([data, filter])

  if (!data) return <><ErrorBox error={error} /><Loading /></>
  const byId = Object.fromEntries(data.checks.map((c) => [c.id, c]))
  const passed = data.checks.filter((c) => c.pass).length
  const shown = data.checks.filter((c) => filter === 'all' || (filter === 'failing' ? !c.pass : c.pass))
  const fwCount = [...new Set(data.checks.flatMap((c) => c.frameworks.map((f) => f.split(':')[0].split(' ').slice(0, 1)[0])))]

  return (
    <div className="space-y-6">
      <PageHeader icon={FlaskConical} eyebrow="Controls as code · continuous assurance" title="Controls lab"
        desc="Twenty controls run as read-only assertions over live state (server/lab.go) after every change, each mapped to NIST SP 800-53 r5, SOX ITGC, HIPAA or CIS. The seed tenant ships with deliberate findings; each module below walks through Problem → Assumptions → Build → Test → Improve to fix them.">
        <Button variant="ghost" onClick={async () => { await reload(); toast('Controls re-evaluated', 'info') }}><RefreshCw className="size-4" /> Re-run</Button>
        <Button onClick={() => downloadFile('iam-lab-writeup.md', writeUp(data.checks), 'text/markdown')}><Download className="size-4" /> Download write-up</Button>
      </PageHeader>
      <ErrorBox error={error} />

      <div className="grid gap-6 lg:grid-cols-[280px_1fr]">
        <Card delay={40}>
          <div className="flex flex-col items-center text-center">
            <Ring value={passed} total={data.checks.length} size={170} label="passing" />
            <p className="mt-4 text-sm text-zinc-400">{data.checks.length - passed === 0 ? 'Clean audit. Every control passes.' : `${data.checks.length - passed} open finding${data.checks.length - passed > 1 ? 's' : ''} to remediate.`}</p>
            <div className="mt-4 flex flex-wrap justify-center gap-1">{fwCount.map((f) => <Badge key={f} tone="neutral">{f}</Badge>)}</div>
          </div>
        </Card>
        <Card title="Live control checks" delay={80} actions={<Seg value={filter} onChange={setFilter} options={['all', 'failing', 'passing']} />}>
          <div key={filter} className="grid gap-2.5 md:grid-cols-2">
            {shown.map((c, i) => (
              <div key={c.id} className={`rounded-xl border p-3.5 animate-fade-up ${c.pass ? 'border-white/[0.06] bg-white/[0.02]' : 'border-rose-500/25 bg-rose-500/[0.04]'}`} style={{ animationDelay: `${i * 35}ms` }}>
                <div className="flex items-start gap-2.5">
                  {c.pass ? <CheckCircle2 className="mt-0.5 size-4 shrink-0 text-emerald-400" /> : <XCircle className="mt-0.5 size-4 shrink-0 text-rose-400" />}
                  <div className="min-w-0">
                    <div className="text-sm font-semibold text-zinc-100"><span className="font-mono text-zinc-500">{c.id}</span> {c.control}</div>
                    <div className="mt-0.5 text-xs text-zinc-500">{c.why}</div>
                    {c.findings.map((f) => <div key={f} className="mt-1.5 text-xs text-rose-300">• {f}</div>)}
                    <div className="mt-2 flex flex-wrap gap-1">{c.frameworks.map((f) => <Tooltip key={f} tip={`Maps to ${f}`}><Badge tone="neutral">{f}</Badge></Tooltip>)}</div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </Card>
      </div>

      <Card title="Concepts" delay={120}>
        <div className="grid gap-4 md:grid-cols-3">
          <Concept caption="Authentication proves identity; authorization decides access. This platform is mostly AuthZ, fed by an IdP that does AuthN.">
            <rect x="10" y="34" width="128" height="74" rx="12" className="fill-violet-500/15 stroke-violet-400" />
            <text x="74" y="66" textAnchor="middle" className="fill-white font-display text-[15px] font-bold">AuthN</text>
            <text x="74" y="86" textAnchor="middle" className="fill-zinc-400 text-[10px]">Who are you?</text>
            <rect x="182" y="34" width="128" height="74" rx="12" className="fill-indigo-500/15 stroke-indigo-400" />
            <text x="246" y="66" textAnchor="middle" className="fill-white font-display text-[15px] font-bold">AuthZ</text>
            <text x="246" y="86" textAnchor="middle" className="fill-zinc-400 text-[10px]">What can you do?</text>
            <path d="M142 71 H176" className="stroke-zinc-500" strokeWidth="1.5" strokeDasharray="4 3"><animate attributeName="stroke-dashoffset" from="14" to="0" dur="1s" repeatCount="indefinite" /></path>
            <text x="160" y="136" textAnchor="middle" className="fill-zinc-500 text-[9.5px]">SAML · OIDC · MFA → roles · entitlements · policy</text>
          </Concept>
          <Concept caption="Every grant has provenance: role (birthright), request (approved exception) or jit (time-boxed elevation).">
            {[['Identity', 14], ['Role / Request / JIT', 112], ['Entitlement', 228]].map(([t, x], i) => (
              <g key={t}><rect x={x} y="46" width={i === 1 ? 100 : 80} height="44" rx="9" className="fill-violet-500/10 stroke-violet-400/70" /><text x={x + (i === 1 ? 50 : 40)} y="72" textAnchor="middle" className="fill-zinc-100 text-[10px] font-semibold">{t}</text></g>
            ))}
            <path d="M94 68 H112 M212 68 H228" className="stroke-zinc-500" strokeWidth="1.5" />
            <text x="160" y="122" textAnchor="middle" className="fill-zinc-500 text-[9.5px]">binding = who + what + why + until when</text>
          </Concept>
          <Concept caption="Least privilege lives at the bottom of the hierarchy: permissions on resources inside systems inside the organization.">
            <rect x="110" y="8" width="100" height="28" rx="7" className="fill-indigo-500/15 stroke-indigo-400" /><text x="160" y="26" textAnchor="middle" className="fill-zinc-100 text-[10px] font-semibold">Organization</text>
            <rect x="40" y="58" width="100" height="28" rx="7" className="fill-violet-500/10 stroke-violet-400/70" /><text x="90" y="76" textAnchor="middle" className="fill-zinc-100 text-[10px]">System</text>
            <rect x="180" y="58" width="100" height="28" rx="7" className="fill-violet-500/10 stroke-violet-400/70" /><text x="230" y="76" textAnchor="middle" className="fill-zinc-100 text-[10px]">System</text>
            {[50, 140, 250].map((x) => <g key={x}><rect x={x - 40} y="108" width="80" height="26" rx="7" className="fill-zinc-950 stroke-white/20" /><text x={x} y="125" textAnchor="middle" className="fill-zinc-400 text-[9.5px]">Entitlement</text></g>)}
            <path d="M160 36 L90 58 M160 36 L230 58 M90 86 L50 108 M90 86 L140 108 M230 86 L250 108" className="stroke-zinc-600" strokeWidth="1.2" fill="none" />
          </Concept>
        </div>
      </Card>

      <Card title="Module walkthroughs" subtitle="Practice the lifecycle, not perfection" delay={160}>
        <div className="hs-accordion-group space-y-2">
          {MODULES.map((m, i) => (
            <div key={m.id} id={`mod-${m.id}`} className={`hs-accordion rounded-xl border border-white/[0.07] bg-white/[0.02] ${i === 0 ? 'active' : ''}`}>
              <button type="button" className="hs-accordion-toggle flex w-full items-center gap-3 px-4 py-3.5 text-start" aria-expanded={i === 0} aria-controls={`mod-body-${m.id}`}>
                <span className="flex-1 font-semibold text-zinc-100">{m.title}</span>
                <span className="flex flex-wrap gap-1">{m.checks.map((id) => byId[id] && <Badge key={id} tone={byId[id].pass ? 'ok' : 'bad'}>{id}</Badge>)}</span>
                <ChevronDown className="size-4 text-zinc-500 transition-transform duration-300 hs-accordion-active:rotate-180" />
              </button>
              <div id={`mod-body-${m.id}`} role="region" className={`hs-accordion-content w-full overflow-hidden transition-[height] duration-300 ${i === 0 ? '' : 'hidden'}`}>
                <div className="px-4 pb-4">
                  <p className="text-sm text-zinc-300"><span className="font-semibold text-white">Problem.</span> {m.problem}</p>
                  <div className="mt-3 grid gap-3 md:grid-cols-2 xl:grid-cols-4">
                    {[['Assumptions', m.assumptions], ['Build', m.build], ['Test', m.test], ['Improve', m.improve]].map(([h, xs]) => (
                      <div key={h} className="rounded-lg bg-zinc-950/50 p-3">
                        <div className="eyebrow mb-1.5 text-violet-300">{h}</div>
                        <ul className="space-y-1 text-xs leading-relaxed text-zinc-400">{xs.map((x) => <li key={x} className="flex gap-1.5"><span className="text-zinc-600">›</span>{x}</li>)}</ul>
                      </div>
                    ))}
                  </div>
                  <a href={`#${m.id}`} className="mt-3 inline-flex items-center gap-1 text-xs font-semibold text-violet-300 hover:text-violet-200">Open module <ArrowRight className="size-3" /></a>
                </div>
              </div>
            </div>
          ))}
        </div>
      </Card>
    </div>
  )
}

function Concept({ children, caption }) {
  return (
    <figure className="rounded-xl border border-white/[0.07] bg-zinc-950/50 p-3 transition-all hover:border-violet-500/30">
      <svg viewBox="0 0 320 150" className="w-full" role="img" aria-label={caption}>{children}</svg>
      <figcaption className="mt-2 text-xs leading-relaxed text-zinc-500">{caption}</figcaption>
    </figure>
  )
}
