import { useEffect, useState } from 'react'
import { ShieldCheck, KeyRound, ArrowRight, ArrowLeft, Copy, Check, LogOut, Fingerprint, Smartphone, ScanFace, LockKeyhole, AlertTriangle, Building2 } from 'lucide-react'
import { api } from '../api.js'
import { Badge, toast } from '../ui.jsx'

// The app's sign-in page. Choose an identity provider, see the demo accounts,
// and understand what happens next. The actual credential check happens at the
// IdP (built-in or Keycloak), never in this page: that is the point of SSO.

const KC_USERS = [
  { u: 'yusuf.ali', role: 'IAM admin', g: 'iam-admins' },
  { u: 'omar.farouk', role: 'Engineering · approver', g: 'engineering, approvers' },
  { u: 'sofia.alvarez', role: 'Service desk', g: 'service-desk' },
]

function CopyChip({ text }) {
  const [ok, setOk] = useState(false)
  return (
    <button type="button" onClick={async () => { try { await navigator.clipboard.writeText(text); setOk(true); setTimeout(() => setOk(false), 1200) } catch { toast('Copy failed', 'err') } }}
      className="inline-flex items-center gap-1.5 rounded-md bg-white/[0.06] px-2 py-0.5 font-mono text-xs text-zinc-200 ring-1 ring-inset ring-white/10 hover:bg-white/10" title={`Copy ${text}`}>
      {text}{ok ? <Check className="size-3 text-emerald-400" /> : <Copy className="size-3 text-zinc-500" />}
    </button>
  )
}

function Provider({ href, icon: Icon, title, sub, badges, disabled, note }) {
  const body = (
    <div className={`group flex items-center gap-4 rounded-2xl border p-4 transition ${disabled ? 'border-white/[0.06] opacity-50' : 'border-white/10 bg-white/[0.03] hover:-translate-y-0.5 hover:border-violet-500/40 hover:bg-violet-500/[0.06]'}`}>
      <span className="inline-flex size-11 shrink-0 items-center justify-center rounded-xl bg-gradient-to-br from-violet-500/25 to-indigo-500/10 ring-1 ring-violet-500/30"><Icon className="size-5 text-violet-200" /></span>
      <div className="min-w-0 flex-1">
        <div className="font-semibold text-white">{title}</div>
        <div className="text-xs text-zinc-400">{sub}</div>
        <div className="mt-1.5 flex flex-wrap gap-1">{badges.map((b) => <Badge key={b} tone="neutral">{b}</Badge>)}</div>
        {note && <div className="mt-1 text-[11px] text-amber-300/80">{note}</div>}
      </div>
      {!disabled && <ArrowRight className="size-5 shrink-0 text-zinc-500 transition group-hover:translate-x-0.5 group-hover:text-violet-300" />}
    </div>
  )
  return disabled ? body : <a href={href} className="block">{body}</a>
}

export default function Login() {
  const [me, setMe] = useState(null)
  const [users, setUsers] = useState([])
  const [demoPw, setDemoPw] = useState('test123')
  const params = new URLSearchParams(window.location.hash.split('?')[1] || '')
  const error = params.get('error')

  useEffect(() => {
    api.me().then(setMe).catch(() => setMe({ authenticated: false, providers: [] }))
    api.idpUsers().then((d) => { setUsers(d.users.filter((u) => !u.breakGlass)); setDemoPw(d.demoPassword) }).catch(() => {})
  }, [])

  const kc = me?.providers?.find((p) => p.id === 'keycloak')
  async function signOut() { await api.logout(); window.location.assign('/#login') ; window.location.reload() }

  return (
    <div className="relative min-h-screen">
      <div aria-hidden className="pointer-events-none fixed inset-0 -z-10 overflow-hidden">
        <div className="grid-bg absolute inset-0 [mask-image:radial-gradient(ellipse_at_top,black_20%,transparent_70%)]" />
        <div className="absolute -top-40 start-1/4 h-96 w-[42rem] rounded-full bg-violet-600/20 blur-[120px] animate-glow" />
        <div className="absolute bottom-0 -end-40 h-80 w-96 rounded-full bg-indigo-600/15 blur-[120px]" />
      </div>

      <div className="mx-auto grid min-h-screen max-w-6xl items-center gap-10 px-4 py-10 lg:grid-cols-2 lg:px-8">
        {/* left: product + what happens */}
        <section className="min-w-0 animate-fade-up">
          <a href="#" className="inline-flex items-center gap-1.5 text-xs font-semibold text-zinc-400 hover:text-zinc-200"><ArrowLeft className="size-3.5" /> Back to the demo</a>
          <div className="mt-6 flex items-center gap-3">
            <span className="relative inline-flex size-12 items-center justify-center rounded-2xl bg-gradient-to-br from-violet-500 to-indigo-600 shadow-lg shadow-violet-900/40"><ShieldCheck className="size-6 text-white" /></span>
            <div>
              <div className="font-display text-xl font-bold text-white">IAM Projects</div>
              <div className="text-[11px] uppercase tracking-[0.16em] text-zinc-500">Identity governance lab</div>
            </div>
          </div>
          <h1 className="mt-8 font-display text-3xl font-extrabold leading-tight text-white sm:text-4xl">
            Sign in with <span className="bg-gradient-to-r from-violet-300 via-indigo-300 to-sky-300 bg-clip-text text-transparent">single sign-on</span>
          </h1>
          <p className="mt-4 max-w-lg text-sm leading-relaxed text-zinc-300">
            This app never sees your password. You authenticate at an identity provider, pass its Conditional Access and MFA checks,
            and come back with a signed token. From then on every action you take is recorded in the audit log under your name.
          </p>
          <ol className="mt-6 space-y-3">
            {[
              [KeyRound, 'Pick an identity provider', 'Built-in OpenID provider, or Keycloak running on its own server.'],
              [LockKeyhole, 'Password, then policy', 'Smart lockout, then Conditional Access looks at location, device and risk.'],
              [Smartphone, 'Prove it with MFA', 'A 6-digit code from an authenticator app (a demo authenticator is built in).'],
              [Fingerprint, 'Signed token, verified', 'Authorization code + PKCE; the RS256 ID token is checked against the IdP\'s keys.'],
            ].map(([I, t, d], i) => (
              <li key={t} className="flex gap-3 animate-fade-up" style={{ animationDelay: `${100 + i * 60}ms` }}>
                <span className="inline-flex size-8 shrink-0 items-center justify-center rounded-lg bg-white/[0.05] ring-1 ring-white/10"><I className="size-4 text-violet-300" /></span>
                <div><div className="text-sm font-semibold text-zinc-100">{t}</div><div className="text-xs text-zinc-400">{d}</div></div>
              </li>
            ))}
          </ol>
        </section>

        {/* right: the card */}
        <section className="panel min-w-0 p-5 sm:p-8 animate-scale-in">
          {error && (
            <div className="mb-5 flex items-start gap-2 rounded-xl border border-rose-500/30 bg-rose-500/10 px-3 py-2.5 text-sm text-rose-200">
              <AlertTriangle className="mt-0.5 size-4 shrink-0" /><div><div className="font-semibold">Sign-in didn't complete</div><div className="text-xs text-rose-200/80">{error}</div></div>
            </div>
          )}

          {me?.authenticated ? (
            <div className="space-y-5">
              <div className="flex items-center gap-3">
                <span className="inline-flex size-12 items-center justify-center rounded-full bg-emerald-500/15 ring-1 ring-emerald-500/30"><ShieldCheck className="size-6 text-emerald-300" /></span>
                <div>
                  <div className="text-lg font-semibold text-white">You're signed in</div>
                  <div className="text-sm text-zinc-400">{me.user.n} · {me.user.u} · via {me.user.idp === 'keycloak' ? 'Keycloak' : 'the built-in IdP'}</div>
                </div>
              </div>
              <div className="flex flex-wrap gap-1.5">{me.user.amr.map((a) => <Badge key={a} tone={a === 'mfa' || a === 'otp' ? 'ok' : 'neutral'}>amr: {a}</Badge>)}{me.user.g.map((g) => <Badge key={g} tone="violet">{g}</Badge>)}</div>
              <div className="grid gap-2 sm:grid-cols-2">
                <a href="#" className="rounded-xl bg-gradient-to-r from-violet-600 to-indigo-600 px-4 py-2.5 text-center text-sm font-semibold text-white hover:from-violet-500 hover:to-indigo-500">Go to the dashboard</a>
                <a href="#sso" className="rounded-xl border border-white/10 px-4 py-2.5 text-center text-sm font-semibold text-zinc-200 hover:bg-white/[0.06]">See my tokens</a>
              </div>
              <button type="button" onClick={signOut} className="inline-flex items-center gap-1.5 text-sm text-rose-300 hover:text-rose-200"><LogOut className="size-4" /> Sign out</button>
            </div>
          ) : (
            <div className="space-y-6">
              <div>
                <h2 className="text-lg font-semibold text-white">Choose how to sign in</h2>
                <p className="text-sm text-zinc-400">Both providers use the same demo accounts and password.</p>
              </div>
              <div className="space-y-3">
                <Provider href="/auth/login" icon={ScanFace} title="Assafwah IdP" sub="Built-in OpenID Connect provider"
                  badges={['OIDC + PKCE', 'Conditional Access', 'TOTP MFA', 'Demo authenticator']} />
                <Provider href="/auth/login?idp=keycloak" icon={Building2} title="Keycloak" sub="keycloak.assafwahinc.com · realm assafwah"
                  badges={['Open-source IdP', 'TOTP enrolment', 'Brute-force lockout']} disabled={!kc?.configured}
                  note={kc && !kc.configured ? 'Not connected on this deployment' : null} />
              </div>

              <div className="rounded-2xl border border-white/[0.07] bg-zinc-950/40 p-4">
                <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
                  <span className="text-sm font-semibold text-zinc-100">Demo accounts</span>
                  <span className="flex items-center gap-2 text-xs text-zinc-400">Password <CopyChip text={demoPw} /></span>
                </div>
                <div className="overflow-x-auto">
                  <table className="min-w-full text-xs">
                    <thead><tr className="text-zinc-500"><th className="py-1.5 text-start font-medium">Username</th><th className="py-1.5 text-start font-medium">Role</th><th className="py-1.5 text-start font-medium">Built-in IdP</th><th className="py-1.5 text-start font-medium">Keycloak</th></tr></thead>
                    <tbody>
                      {[...new Set([...users.map((u) => u.username), ...KC_USERS.map((k) => k.u)])].map((name) => {
                        const b = users.find((u) => u.username === name)
                        const k = KC_USERS.find((x) => x.u === name)
                        return (
                          <tr key={name} className="border-t border-white/[0.05]">
                            <td className="py-2 pe-3"><CopyChip text={name} /></td>
                            <td className="py-2 pe-3 text-zinc-300">{k?.role || b?.groups?.filter((g) => g !== 'all-staff').join(', ')}</td>
                            <td className="py-2 pe-3">{b ? (b.mfaEnrolled ? <Badge tone="ok">MFA ready</Badge> : <Badge tone="warn">enrols MFA</Badge>) : <span className="text-zinc-600">—</span>}</td>
                            <td className="py-2">{k ? <Badge tone="info">enrols TOTP</Badge> : <span className="text-zinc-600">—</span>}</td>
                          </tr>
                        )
                      })}
                    </tbody>
                  </table>
                </div>
                <p className="mt-3 text-[11px] leading-relaxed text-zinc-500">
                  Built-in IdP: codes come from the demo authenticator on the sign-in page. Keycloak: scan its QR code with Google or Microsoft Authenticator on first sign-in.
                  The Keycloak admin account is for administering Keycloak, not for signing in here.
                </p>
              </div>
              <p className="text-center text-[11px] text-zinc-500">Fictional people and data. Every sign-in attempt appears on Identity threat detection.</p>
            </div>
          )}
        </section>
      </div>
    </div>
  )
}
