import { useEffect, useState } from 'react'
import QRCode from 'qrcode'
import { ShieldCheck, KeyRound, Smartphone, MapPin, Laptop, Mail, ArrowRight, Lock, ShieldX, ChevronDown } from 'lucide-react'
import { Button, Seg, Badge } from '../ui.jsx'
import { CAEvalView, AuthenticatorTile } from '../components.jsx'
import { api } from '../api.js'

// Hosted sign-in page of the built-in IdP (the equivalent of Entra's or
// Keycloak's login screen). Reached via /idp/authorize → /#signin?txn=…

async function post(path, body) {
  const res = await fetch(`/idp/api/txn/${path}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })
  const data = await res.json().catch(() => ({}))
  return { ok: res.ok, status: res.status, data }
}

export default function SignIn() {
  const txn = new URLSearchParams(window.location.hash.split('?')[1] || '').get('txn')
  const [info, setInfo] = useState(null)
  const [err, setErr] = useState('')
  const [step, setStep] = useState('password') // password | mfa | enroll | blocked | done
  const [form, setForm] = useState({ username: 'yusuf.ali', password: '', location: 'nashville', device: 'managed', client: 'browser' })
  const [ev, setEv] = useState(null)
  const [code, setCode] = useState('')
  const [enroll, setEnroll] = useState(null)
  const [qr, setQr] = useState('')
  const [busy, setBusy] = useState(false)
  const [secrets, setSecrets] = useState({})
  const [ctxOpen, setCtxOpen] = useState(false)

  useEffect(() => {
    if (!txn) { setErr('No sign-in in progress. Start from the application.'); return }
    api.txn(txn).then(setInfo).catch((e) => setErr(e.message))
    api.idpUsers().then((d) => setSecrets(Object.fromEntries(d.users.filter((u) => u.demoTotpSecret).map((u) => [u.username, u.demoTotpSecret])))).catch(() => {})
  }, [txn])

  useEffect(() => { if (enroll?.otpauth) QRCode.toDataURL(enroll.otpauth, { margin: 1, width: 180, color: { dark: '#0a0a0b', light: '#ffffff' } }).then(setQr) }, [enroll])

  function handle(r) {
    setBusy(false)
    if (r.data.evaluation) setEv(r.data.evaluation)
    if (!r.ok) {
      if (r.status === 403 && r.data.evaluation) setStep('blocked')
      setErr(r.data.error || 'Sign-in failed')
      return
    }
    setErr('')
    if (r.data.next === 'done') { setStep('done'); setTimeout(() => window.location.assign(r.data.redirect), 700) }
    else if (r.data.next === 'enroll') { setEnroll(r.data); setStep('enroll') }
    else setStep(r.data.next)
  }

  const submitPw = async (e) => { e.preventDefault(); setBusy(true); handle(await post(`${txn}/password`, form)) }
  const submitMFA = async (c = code) => { setBusy(true); handle(await post(`${txn}/mfa`, { code: c })) }
  const submitEnroll = async (c = code) => { setBusy(true); handle(await post(`${txn}/enroll`, { code: c })) }

  const loc = info?.locations?.find((l) => l.key === form.location)

  return (
    <div className="flex min-h-screen items-center justify-center px-4 py-10">
      <div className="w-full max-w-md animate-scale-in">
        <div className="mb-6 flex items-center justify-center gap-2.5">
          <span className="inline-flex size-10 items-center justify-center rounded-xl bg-gradient-to-br from-violet-500 to-indigo-600 shadow-lg shadow-violet-900/40"><ShieldCheck className="size-5 text-white" /></span>
          <div>
            <div className="font-display text-base font-bold text-white">Assafwah IdP</div>
            <div className="text-[10px] uppercase tracking-[0.16em] text-zinc-500">OpenID Connect · demo tenant</div>
          </div>
        </div>

        <div className="panel overflow-hidden">
          <div className="border-b border-white/[0.06] px-6 py-4">
            <div className="text-xs text-zinc-500">Sign in to continue to</div>
            <div className="font-semibold text-zinc-100">{info?.client || '…'}</div>
            {info && <div className="mt-1 font-mono text-[10px] text-zinc-500">scope: {info.scope} · PKCE S256</div>}
          </div>

          <div className="p-6">
            {err && <div className="mb-4 flex items-start gap-2 rounded-lg border border-rose-500/30 bg-rose-500/10 px-3 py-2 text-sm text-rose-300 animate-fade-in"><Lock className="mt-0.5 size-4 shrink-0" />{err}</div>}

            {step === 'password' && info && (
              <form onSubmit={submitPw} className="space-y-4">
                <div>
                  <label className="label" htmlFor="u">Username</label>
                  <input id="u" className="input" autoComplete="username" value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })} />
                  <div className="mt-2 flex flex-wrap gap-1.5">
                    {info.users.map((u) => (
                      <button key={u.username} type="button" onClick={() => setForm({ ...form, username: u.username })}
                        className={`rounded-full px-2 py-0.5 text-[11px] ring-1 ring-inset transition ${form.username === u.username ? 'bg-violet-500/20 text-violet-200 ring-violet-500/40' : 'text-zinc-400 ring-white/10 hover:text-zinc-200'}`}>
                        {u.username}{u.breakGlass ? ' ⚠' : ''}{!u.mfaEnrolled ? ' (no MFA yet)' : ''}
                      </button>
                    ))}
                  </div>
                </div>
                <div>
                  <label className="label" htmlFor="p">Password</label>
                  <input id="p" type="password" className="input" autoComplete="current-password" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} />
                  <p className="mt-1.5 text-[11px] text-zinc-500">Demo password for every user: <button type="button" className="code" onClick={() => setForm({ ...form, password: info.demoPassword })}>{info.demoPassword}</button> (click to fill). Five wrong tries trigger smart lockout.</p>
                </div>

                <div className="rounded-xl border border-white/[0.07] bg-white/[0.02]">
                  <button type="button" onClick={() => setCtxOpen(!ctxOpen)} className="flex w-full items-center justify-between px-3 py-2.5 text-start">
                    <span className="text-xs font-semibold text-zinc-300">Simulate where you're signing in from</span>
                    <span className="flex items-center gap-2 text-[11px] text-zinc-500">{loc?.city} · {form.device} · {form.client}<ChevronDown className={`size-3.5 transition ${ctxOpen ? 'rotate-180' : ''}`} /></span>
                  </button>
                  {ctxOpen && (
                    <div className="space-y-3 border-t border-white/[0.06] p-3 animate-fade-in">
                      <div>
                        <label className="label flex items-center gap-1.5"><MapPin className="size-3" /> Location / IP</label>
                        <select className="input" value={form.location} onChange={(e) => setForm({ ...form, location: e.target.value })}>
                          {info.locations.map((l) => <option key={l.key} value={l.key}>{l.city}, {l.countryName} · {l.ip}</option>)}
                        </select>
                      </div>
                      <div className="flex flex-wrap gap-3">
                        <div><label className="label flex items-center gap-1.5"><Laptop className="size-3" /> Device</label><Seg value={form.device} onChange={(v) => setForm({ ...form, device: v })} options={['managed', 'unmanaged']} /></div>
                        <div><label className="label flex items-center gap-1.5"><Mail className="size-3" /> Client</label><Seg value={form.client} onChange={(v) => setForm({ ...form, client: v })} options={[{ value: 'browser', label: 'Browser' }, { value: 'legacy-imap', label: 'Legacy IMAP' }]} /></div>
                      </div>
                      <p className="text-[11px] leading-relaxed text-zinc-500">Conditional Access evaluates these signals. Try Moscow (geo-block), the Tor exit (high risk), an unmanaged device (step-up MFA) or legacy IMAP (allowed until CA003 is switched on).</p>
                    </div>
                  )}
                </div>
                <Button type="submit" className="w-full" disabled={busy}>Sign in <ArrowRight className="size-4" /></Button>
              </form>
            )}

            {step === 'mfa' && (
              <div className="space-y-4 animate-fade-up">
                <div className="flex items-center gap-2 text-sm text-zinc-200"><Smartphone className="size-4 text-violet-300" /> Enter the 6-digit code from your authenticator app</div>
                <CAEvalView ev={ev} compact />
                <input className="input text-center font-mono text-2xl tracking-[0.5em]" inputMode="numeric" maxLength={6} autoFocus value={code} onChange={(e) => setCode(e.target.value.replace(/\D/g, ''))} onKeyDown={(e) => e.key === 'Enter' && submitMFA()} />
                <Button className="w-full" disabled={busy || code.length !== 6} onClick={() => submitMFA()}>Verify</Button>
                {secrets[form.username] && <>
                  <div className="eyebrow pt-2">Demo authenticator (stands in for the phone app)</div>
                  <AuthenticatorTile label={`Assafwah IdP: ${form.username}`} secret={secrets[form.username]} onUse={(c) => { setCode(c); submitMFA(c) }} />
                </>}
              </div>
            )}

            {step === 'enroll' && enroll && (
              <div className="space-y-4 animate-fade-up">
                <div className="flex items-center gap-2 text-sm text-zinc-200"><KeyRound className="size-4 text-amber-300" /> Your organisation requires MFA. Set up an authenticator app.</div>
                <ol className="list-decimal space-y-1 ps-5 text-xs text-zinc-400">
                  <li>Scan the QR code with Microsoft Authenticator, Google Authenticator or 1Password.</li>
                  <li>Enter the 6-digit code it shows to confirm.</li>
                </ol>
                <div className="flex flex-col items-center gap-2">
                  {qr && <img src={qr} alt="TOTP enrolment QR code" className="rounded-lg" width={180} height={180} />}
                  <code className="code break-all text-center text-[11px]">{enroll.secret}</code>
                </div>
                <input className="input text-center font-mono text-2xl tracking-[0.5em]" inputMode="numeric" maxLength={6} value={code} onChange={(e) => setCode(e.target.value.replace(/\D/g, ''))} onKeyDown={(e) => e.key === 'Enter' && submitEnroll()} />
                <Button className="w-full" disabled={busy || code.length !== 6} onClick={() => submitEnroll()}>Confirm and continue</Button>
                <div className="eyebrow pt-2">No phone handy? Demo authenticator</div>
                <AuthenticatorTile label={`Assafwah IdP: ${form.username}`} secret={enroll.secret} onUse={(c) => { setCode(c); submitEnroll(c) }} />
              </div>
            )}

            {step === 'blocked' && (
              <div className="space-y-4 animate-fade-up">
                <div className="flex items-center gap-2 text-sm font-semibold text-rose-300"><ShieldX className="size-4" /> You can't get there from here</div>
                <p className="text-xs text-zinc-400">Conditional Access evaluated every policy below. One with a Block grant matched, so the sign-in stopped after the password step. It's in the sign-in log.</p>
                <CAEvalView ev={ev} />
                <Button variant="ghost" className="w-full" onClick={() => { setStep('password'); setErr(''); setEv(null) }}>Try different conditions</Button>
              </div>
            )}

            {step === 'done' && (
              <div className="flex flex-col items-center gap-3 py-6 text-center animate-scale-in">
                <ShieldCheck className="size-10 text-emerald-400" />
                <div className="font-semibold text-white">Signed in</div>
                <div className="text-xs text-zinc-400">Redirecting back with an authorization code…</div>
                {ev && <Badge tone="ok">{ev.applied?.length ? `Policies applied: ${ev.applied.join(', ')}` : 'No policy required MFA'}</Badge>}
              </div>
            )}
          </div>
        </div>
        <p className="mt-4 text-center text-xs"><a href="/#login" className="font-semibold text-violet-300 hover:text-violet-200">← Other sign-in options</a></p>
        <p className="mt-2 text-center text-[11px] text-zinc-500">Fictional users. Every attempt is written to the sign-in log on the Identity threat detection page.</p>
      </div>
    </div>
  )
}
