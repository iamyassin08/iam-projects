import { useEffect, useState } from 'react'
import { ShieldCheck, ArrowRight, Copy, Check, LogOut, Fingerprint, Smartphone, KeyRound, LockKeyhole, AlertTriangle, ChevronDown, Building2, UserRound } from 'lucide-react'
import { api } from '../api.js'
import { Badge, toast, usePreline } from '../ui.jsx'
import { refreshMe, displayName } from '../me.js'
import { UserAvatar } from '../components.jsx'
import IdpFlow from './IdpFlow.jsx'

// Sign-in page in the style of Preline's auth templates
// (https://preline.co/examples/forms-authentication.html): centred card,
// provider buttons, an "Or" divider, then the form. The password itself is
// entered at the identity provider, never here: that is the point of SSO.

const KC_USERS = ['yusuf.ali', 'omar.farouk', 'sofia.alvarez']
const ROLES = { 'yusuf.ali': 'IAM admin', 'omar.farouk': 'Engineering · approver', 'priya.raman': 'Finance', 'sofia.alvarez': 'Service desk' }

function KeycloakMark({ src }) {
  const [bad, setBad] = useState(!src)
  return bad
    ? <Building2 className="size-5 text-sky-300" />
    : <img src={src} alt="Keycloak" className="size-5" onError={() => setBad(true)} />
}

function CopyBtn({ text }) {
  const [ok, setOk] = useState(false)
  return (
    <button type="button" onClick={async () => { try { await navigator.clipboard.writeText(text); setOk(true); setTimeout(() => setOk(false), 1200) } catch { toast('Copy failed', 'err') } }}
      className="inline-flex items-center gap-1 rounded-md px-1.5 py-0.5 font-mono text-xs text-violet-200 ring-1 ring-inset ring-violet-500/30 hover:bg-violet-500/10" aria-label={`Copy ${text}`}>
      {text}{ok ? <Check className="size-3 text-emerald-400" /> : <Copy className="size-3" />}
    </button>
  )
}

export default function Login() {
  const [me, setMe] = useState(null)
  const [users, setUsers] = useState([])
  const [demoPw, setDemoPw] = useState('test123')
  const [username, setUsername] = useState('yusuf.ali')
  const error = new URLSearchParams(window.location.hash.split('?')[1] || '').get('error')
  usePreline([me])

  useEffect(() => {
    api.me().then(setMe).catch(() => setMe({ authenticated: false, providers: [] }))
    api.idpUsers().then((d) => { setUsers(d.users.filter((u) => !u.breakGlass)); setDemoPw(d.demoPassword) }).catch(() => {})
  }, [])

  const kc = me?.providers?.find((p) => p.id === 'keycloak')
  const hint = encodeURIComponent(username.trim())
  const builtinHref = `/auth/login${hint ? `?login_hint=${hint}` : ''}`
  const kcHref = `/auth/login?idp=keycloak&return=login${KC_USERS.includes(username.trim()) ? `&login_hint=${hint}` : ''}`
  // Opens the OIDC transaction without navigating: the IdP answers JSON when asked.
  async function startBuiltin(u) {
    const res = await fetch(`/auth/login?return=login&login_hint=${encodeURIComponent(u.trim())}`, { headers: { Accept: 'application/json' }, credentials: 'same-origin' })
    const d = await res.json().catch(() => ({}))
    if (!res.ok || !d.txn) throw new Error(d.error || 'Could not start sign-in')
    return d.txn
  }
  const names = [...new Set([...users.map((u) => u.username), ...KC_USERS])]
  async function signOut() { await api.logout(); await refreshMe(); setMe(await api.me()); toast('Signed out') }

  const btn = 'w-full py-3 px-4 inline-flex justify-center items-center gap-x-2 text-sm font-medium rounded-lg border shadow-2xs transition focus:outline-hidden'
  const btnGhost = `${btn} border-white/10 bg-zinc-900 text-white hover:bg-zinc-800 focus:bg-zinc-800`

  return (
    <div className="mx-auto w-full max-w-md py-4 sm:py-8">
      {error && (
        <div role="alert" className="mb-4 flex items-start gap-2 rounded-xl border border-rose-500/30 bg-rose-500/10 p-4 text-sm text-rose-200 animate-fade-in">
          <AlertTriangle className="mt-0.5 size-4 shrink-0" />
          <div><h3 className="font-semibold">Sign-in didn't complete</h3><p className="mt-1 text-xs text-rose-200/80">{error}</p></div>
        </div>
      )}

      <div className="rounded-xl border border-white/10 bg-zinc-900/80 shadow-2xs backdrop-blur animate-scale-in">
        <div className="p-4 sm:p-7">
          {me?.authenticated ? (
            <div className="text-center">
              <div className="flex justify-center"><UserAvatar me={me} size="size-16" text="text-lg" /></div>
              <h1 className="mt-4 block text-2xl font-bold text-white">You're signed in</h1>
              <p className="mt-2 text-sm text-zinc-400">{displayName(me)} · {me.user.u} · via {me.user.idp === 'keycloak' ? 'Keycloak' : 'Assafwah IdP'}</p>
              <div className="mt-3 flex flex-wrap justify-center gap-1.5">{me.user.amr.map((a) => <Badge key={a} tone={a === 'mfa' || a === 'otp' ? 'ok' : 'neutral'}>amr: {a}</Badge>)}</div>
              <div className="mt-6 grid gap-2">
                <a href="#" className={`${btn} border-transparent bg-violet-600 text-white hover:bg-violet-700`}>Go to the dashboard <ArrowRight className="size-4" /></a>
                <a href="#profile" className={btnGhost}><UserRound className="size-4" /> My profile</a>
                <a href="#sso" className={btnGhost}><Fingerprint className="size-4" /> View my tokens</a>
                <button type="button" onClick={signOut} className={`${btn} border-rose-500/20 bg-transparent text-rose-300 hover:bg-rose-500/10`}><LogOut className="size-4" /> Sign out</button>
              </div>
            </div>
          ) : (<>
            <div className="text-center">
              <span className="mx-auto inline-flex size-12 items-center justify-center rounded-xl bg-gradient-to-br from-violet-500 to-indigo-600 shadow-lg shadow-violet-900/40"><ShieldCheck className="size-6 text-white" /></span>
              <h1 className="mt-4 block text-2xl font-bold text-white">Sign in</h1>
              <p className="mt-2 text-sm text-zinc-400">
                No account needed. Use a demo account, password <CopyBtn text={demoPw} />
              </p>
            </div>

            <div className="mt-5">
              {/* federated provider, Preline "Sign in with Google" style */}
              {kc?.configured ? (
                <a href={kcHref} className={btnGhost}>
                  <KeycloakMark src={kc.logo} /> Sign in with Keycloak
                </a>
              ) : (
                <span className={`${btn} cursor-not-allowed border-white/[0.06] bg-zinc-900 text-zinc-500`} title="Set OIDC_ISSUER to enable">
                  <Building2 className="size-5" /> Keycloak isn't connected here
                </span>
              )}
              {kc?.configured && <p className="mt-1.5 text-center text-[11px] text-zinc-500">Keycloak users: {KC_USERS.join(', ')}. You'll enter the password on Keycloak's page.</p>}

              <div className="flex items-center py-4 text-xs uppercase text-zinc-500 before:me-6 before:flex-1 before:border-t before:border-white/10 after:ms-6 after:flex-1 after:border-t after:border-white/10">Or with Assafwah IdP</div>

              {/* built-in IdP, embedded: password, Conditional Access and MFA happen right here */}
              <IdpFlow start={startBuiltin} username={username} setUsername={setUsername} roles={ROLES} />
              <p className="mt-3 text-center text-[11px] text-zinc-500">
                Same OIDC flow (PKCE, state, nonce) without leaving this page. <a href={builtinHref} className="text-violet-300 hover:underline">Use the hosted IdP page</a>
              </p>
            </div>
            </>)}
        </div>
      </div>

      {/* account table + how it works (Preline accordion) */}
      {!me?.authenticated && (
        <div className="mt-4 hs-accordion-group space-y-3">
          <div className="hs-accordion rounded-xl border border-white/10 bg-zinc-900/60" id="acc-accounts">
            <button type="button" className="hs-accordion-toggle flex w-full items-center justify-between gap-x-3 px-5 py-3 text-start text-sm font-semibold text-zinc-200" aria-expanded="false" aria-controls="acc-accounts-body">
              Demo accounts and MFA status <ChevronDown className="size-4 text-zinc-500 transition hs-accordion-active:rotate-180" />
            </button>
            <div id="acc-accounts-body" role="region" className="hs-accordion-content hidden w-full overflow-hidden transition-[height] duration-300">
              <div className="overflow-x-auto px-5 pb-4">
                <table className="min-w-full text-xs">
                  <thead><tr className="text-zinc-500"><th className="py-1.5 text-start font-medium">Username</th><th className="py-1.5 text-start font-medium">Assafwah IdP</th><th className="py-1.5 text-start font-medium">Keycloak</th></tr></thead>
                  <tbody>{names.map((n) => { const b = users.find((u) => u.username === n); return (
                    <tr key={n} className="border-t border-white/[0.05]">
                      <td className="py-2 pe-3"><CopyBtn text={n} /></td>
                      <td className="py-2 pe-3">{b ? (b.mfaEnrolled ? <Badge tone="ok">MFA ready</Badge> : <Badge tone="warn">enrols MFA</Badge>) : <span className="text-zinc-600">—</span>}</td>
                      <td className="py-2">{KC_USERS.includes(n) ? <Badge tone="info">enrols TOTP</Badge> : <span className="text-zinc-600">—</span>}</td>
                    </tr>) })}</tbody>
                </table>
                <p className="mt-3 text-[11px] leading-relaxed text-zinc-500">Assafwah IdP: codes come from the demo authenticator on its sign-in page. Keycloak: scan its QR code with Google or Microsoft Authenticator. The Keycloak admin account administers Keycloak; it can't sign in here.</p>
              </div>
            </div>
          </div>
          <div className="hs-accordion rounded-xl border border-white/10 bg-zinc-900/60" id="acc-how">
            <button type="button" className="hs-accordion-toggle flex w-full items-center justify-between gap-x-3 px-5 py-3 text-start text-sm font-semibold text-zinc-200" aria-expanded="false" aria-controls="acc-how-body">
              What happens when I sign in? <ChevronDown className="size-4 text-zinc-500 transition hs-accordion-active:rotate-180" />
            </button>
            <div id="acc-how-body" role="region" className="hs-accordion-content hidden w-full overflow-hidden transition-[height] duration-300">
              <ol className="space-y-3 px-5 pb-4">
                {[[KeyRound, 'You pick an identity provider', 'This app sends you there with a PKCE challenge, state and nonce.'], [LockKeyhole, 'Password, then policy', 'Smart lockout, then Conditional Access checks location, device and risk.'], [Smartphone, 'MFA', 'A 6-digit code from an authenticator app.'], [Fingerprint, 'Signed token, verified', 'The RS256 ID token is checked against the IdP\'s keys before a session is created.']].map(([I, t, d]) => (
                  <li key={t} className="flex gap-3"><I className="mt-0.5 size-4 shrink-0 text-violet-300" /><div><div className="text-sm text-zinc-100">{t}</div><div className="text-xs text-zinc-500">{d}</div></div></li>
                ))}
              </ol>
            </div>
          </div>
        </div>
      )}
      <p className="mt-4 text-center text-xs text-zinc-500">Fictional people and data. Every sign-in attempt shows up on <a href="#monitoring" className="text-violet-300 hover:underline">Identity threat detection</a>.</p>
    </div>
  )
}
