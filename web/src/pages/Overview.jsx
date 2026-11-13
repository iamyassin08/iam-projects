import {
  Users, ShieldAlert, Timer, ClipboardCheck, AlertOctagon, Flame, RotateCcw, ArrowRight, FlaskConical, Plug, KeyRound,
  Grid3x3, Radar, CheckCircle2, XCircle, Fingerprint, Smartphone, Vault, Cloud, Activity, Terminal, BookOpen,
} from 'lucide-react'
import { api } from '../api.js'
import { useLoad, Stat, Card, Ring, Badge, Button, ErrorBox, Loading, ask, toast, Avatar, levelTone, Progress, usePreline } from '../ui.jsx'

const MODULES = [
  { id: 'jml', icon: Users, title: 'Lifecycle (JML)', text: 'Joiner, mover, leaver with birthright RBAC. Movers lose old access in the same event.', tag: 'NIST AC-2' },
  { id: 'scim', icon: Plug, title: 'SCIM 2.0 API', text: 'RFC 7644 Users and Groups endpoints so Entra ID or Okta can provision in.', tag: 'RFC 7643/7644' },
  { id: 'requests', icon: KeyRound, title: 'Access requests', text: 'Justified requests with SoD checks and documented risk acceptance.', tag: 'NIST AC-5' },
  { id: 'certifications', icon: ClipboardCheck, title: 'Access reviews', text: 'Campaigns routed to managers, with revoke-on-non-response at close.', tag: 'SOX UAR' },
  { id: 'pam', icon: Timer, title: 'Just-in-time access', text: 'Time-boxed elevation with tickets, break-glass and automatic expiry.', tag: 'NIST AC-6(5)' },
  { id: 'roles', icon: Grid3x3, title: 'Role matrix', text: 'RBAC design that blocks toxic combinations at the role level.', tag: 'Least privilege' },
  { id: 'risk', icon: Radar, title: 'Risk & reconciliation', text: 'Explainable risk scores, orphan and rogue account detection.', tag: 'NIST AC-2(3)' },
  { id: 'sso', icon: Fingerprint, title: 'SSO & Keycloak', text: 'Built-in OpenID Connect provider with PKCE, plus Keycloak at keycloak.assafwahinc.com.', tag: 'OIDC · SAML' },
  { id: 'mfa', icon: Smartphone, title: 'MFA & Conditional Access', text: 'Entra-style policies, What-If, TOTP enrolment, legacy-auth block.', tag: 'NIST IA-2(1)' },
  { id: 'vault', icon: Vault, title: 'Credential vault', text: 'AES-256-GCM vault, step-up MFA checkout, rotate on check-in.', tag: 'PAM' },
  { id: 'cloud', icon: Cloud, title: 'Cloud IAM', text: 'AWS policy simulator with boundaries, Azure RBAC with PIM.', tag: 'Least privilege' },
  { id: 'monitoring', icon: Activity, title: 'Threat detection', text: 'Spray, brute force, impossible travel, MFA fatigue, with KQL.', tag: 'MITRE ATT&CK' },
  { id: 'automation', icon: Terminal, title: 'Automation', text: 'HR feed to joiner/mover/leaver over SCIM, in Python and PowerShell.', tag: 'Python' },
  { id: 'lab', icon: FlaskConical, title: 'Controls lab', text: '20 live, testable controls mapped to NIST 800-53, SOX, HIPAA and CIS.', tag: 'Audit-ready' },
]

export default function Overview() {
  const [data, reload, error] = useLoad({ summary: api.summary, checks: api.checks, risk: api.risk })
  usePreline([data])

  async function reset() {
    const ok = await ask({ title: 'Reset demo tenant?', message: 'This restores the seed data, including the twelve deliberate audit findings. Anything changed since will be lost.', input: false, confirm: 'Reset', tone: 'danger' })
    if (!ok) return
    try { await api.reset(); await reload(); toast('Demo tenant reset to seed data') } catch (e) { toast(e.message, 'err') }
  }

  if (!data) return <><ErrorBox error={error} /><Loading /></>
  const { summary: s, checks, risk } = data
  const passing = checks.filter((c) => c.pass).length
  const failing = checks.filter((c) => !c.pass)

  return (
    <div className="space-y-6">
      <section className="relative overflow-hidden rounded-3xl border border-white/[0.07] bg-gradient-to-br from-violet-950/60 via-zinc-900/60 to-zinc-950 p-6 sm:p-10 animate-fade-up">
        <div aria-hidden className="absolute -end-20 -top-20 size-72 rounded-full bg-violet-500/20 blur-3xl animate-glow" />
        <div className="relative grid items-center gap-8 lg:grid-cols-[1fr_auto]">
          <div>
            <Badge tone="violet" dot>Live demo tenant · Go API + React</Badge>
            <h1 className="mt-4 font-display text-3xl font-extrabold leading-tight text-white sm:text-5xl">
              Identity governance, <span className="bg-gradient-to-r from-violet-300 via-indigo-300 to-sky-300 bg-clip-text text-transparent">built and audited</span>
            </h1>
            <p className="mt-4 max-w-2xl text-sm leading-relaxed text-zinc-300 sm:text-base">
              A working IAM platform covering identity lifecycle, SCIM provisioning, SSO with its own OpenID provider and Keycloak, MFA and Conditional Access,
              access reviews, just-in-time access with a credential vault, cloud IAM policies and identity threat detection. Every control is a testable assertion mapped to NIST SP 800-53, SOX ITGC and HIPAA.
            </p>
            <div className="mt-6 flex flex-wrap gap-2">
              <a href="#guide"><Button><BookOpen className="size-4" /> Project guide: all 10 projects</Button></a>
              <a href="#lab"><Button variant="ghost"><FlaskConical className="size-4" /> Run the controls lab</Button></a>
              <a href="#scim"><Button variant="ghost"><Plug className="size-4" /> Try the SCIM API</Button></a>
              <Button variant="subtle" onClick={reset}><RotateCcw className="size-4" /> Reset demo</Button>
            </div>
          </div>
          <div className="flex flex-col items-center gap-2 justify-self-center animate-float">
            <Ring value={passing} total={checks.length} size={168} label="controls passing" />
            <div className="text-xs text-zinc-400">{failing.length} open audit finding{failing.length === 1 ? '' : 's'}</div>
          </div>
        </div>
      </section>

      <ErrorBox error={error} />

      <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
        <Stat label="Active identities" value={s.activeIdentities} icon={Users} delay={0} />
        <Stat label="Privileged grants" value={s.privilegedGrants} icon={ShieldAlert} tone="warn" delay={60} />
        <Stat label="Live JIT sessions" value={s.activeJIT} icon={Timer} tone="info" delay={120} />
        <Stat label="Pending reviews" value={s.pendingReviews} icon={ClipboardCheck} tone="violet" delay={180} />
        <Stat label="Failing controls" value={s.failingControls} icon={AlertOctagon} tone={s.failingControls ? 'bad' : 'ok'} delay={240} />
        <Stat label="High-risk identities" value={s.highRisk} icon={Flame} tone={s.highRisk ? 'bad' : 'ok'} delay={300} />
      </div>

      <div className="grid gap-6 lg:grid-cols-5">
        <Card className="lg:col-span-3" title="Open audit findings" subtitle="Failing controls from the live control checks" delay={120}
          actions={<a href="#lab" className="text-xs font-semibold text-violet-300 hover:text-violet-200">All controls →</a>}>
          {failing.length === 0 ? (
            <div className="flex items-center gap-2 text-sm text-emerald-300"><CheckCircle2 className="size-4" /> Every control passes.</div>
          ) : (
            <ul className="space-y-3">
              {failing.map((c, i) => (
                <li key={c.id} className="flex gap-3 rounded-xl border border-rose-500/15 bg-rose-500/[0.04] p-3 animate-fade-up" style={{ animationDelay: `${150 + i * 50}ms` }}>
                  <XCircle className="mt-0.5 size-4 shrink-0 text-rose-400" />
                  <div className="min-w-0">
                    <div className="text-sm font-semibold text-zinc-100">{c.id} · {c.control}</div>
                    <div className="mt-0.5 truncate text-xs text-rose-300/90">{c.findings[0]}{c.findings.length > 1 && ` (+${c.findings.length - 1} more)`}</div>
                    <div className="mt-1.5 flex flex-wrap gap-1">{c.frameworks.slice(0, 2).map((f) => <Badge key={f} tone="neutral">{f}</Badge>)}</div>
                  </div>
                </li>
              ))}
            </ul>
          )}
        </Card>

        <Card className="lg:col-span-2" title="Riskiest identities" subtitle={`Average score ${risk.average} / 100`} delay={180}
          actions={<a href="#risk" className="text-xs font-semibold text-violet-300 hover:text-violet-200">Explain →</a>}>
          <ul className="space-y-3.5">
            {risk.identities.slice(0, 5).map((r) => (
              <li key={r.identityId} className="flex items-center gap-3">
                <Avatar name={r.name} />
                <div className="min-w-0 flex-1">
                  <div className="flex items-center justify-between gap-2">
                    <span className="truncate text-sm font-medium text-zinc-100">{r.name}</span>
                    <Badge tone={levelTone[r.level]}>{r.score} · {r.level}</Badge>
                  </div>
                  <Progress value={r.score} tone={r.score >= 50 ? 'bad' : r.score >= 25 ? 'warn' : 'ok'} className="mt-1.5" />
                </div>
              </li>
            ))}
          </ul>
        </Card>
      </div>

      <div>
        <div className="eyebrow mb-3">Modules</div>
        <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
          {MODULES.map((m, i) => (
            <a key={m.id} href={`#${m.id}`}
              className="panel group relative flex flex-col overflow-hidden p-5 transition-all duration-300 hover:-translate-y-1 hover:border-violet-500/40 hover:shadow-2xl hover:shadow-violet-950/50 animate-fade-up"
              style={{ animationDelay: `${200 + i * 50}ms` }}>
              <span aria-hidden className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-violet-400/60 to-transparent opacity-0 transition-opacity group-hover:opacity-100" />
              <m.icon className="size-6 text-violet-300 transition-transform duration-300 group-hover:scale-110" />
              <div className="mt-4 font-semibold text-white">{m.title}</div>
              <p className="mt-1.5 flex-1 text-sm text-zinc-400">{m.text}</p>
              <div className="mt-4 flex items-center justify-between">
                <Badge tone="neutral">{m.tag}</Badge>
                <ArrowRight className="size-4 text-zinc-500 transition-all group-hover:translate-x-1 group-hover:text-violet-300" />
              </div>
            </a>
          ))}
        </div>
      </div>
    </div>
  )
}
