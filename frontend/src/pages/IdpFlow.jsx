import { useEffect, useState } from 'react'
import QRCode from 'qrcode'
import { ShieldCheck, KeyRound, Smartphone, MapPin, Laptop, Mail, ArrowRight, Lock, ShieldX, ChevronDown, Eye, EyeOff } from 'lucide-react'
import { Button, Seg, Badge } from '../ui.jsx'
import { CAEvalView, AuthenticatorTile } from '../components.jsx'
import { api } from '../api.js'

// The built-in IdP's password → Conditional Access → MFA steps. Used by the
// hosted page (#signin, txn already exists) and embedded in the app's own
// sign-in page (#login), where `start` opens the OIDC transaction on submit.

async function post(path, body) {
  const res = await fetch(`/idp/api/txn/${path}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })
  const data = await res.json().catch(() => ({}))
  return { ok: res.ok, status: res.status, data }
}

export default function IdpFlow({ txn: initialTxn = null, start, username, setUsername, roles = {} }) {
  const [txn, setTxn] = useState(initialTxn)
  const [meta, setMeta] = useState(null) // users, locations, demo password
  const [err, setErr] = useState('')
  const [step, setStep] = useState('password') // password | mfa | enroll | blocked | done
  const [form, setForm] = useState({ password: '', location: 'nashville', device: 'managed', client: 'browser' })
  const [show, setShow] = useState(false)
  const [ev, setEv] = useState(null)
  const [code, setCode] = useState('')
  const [enroll, setEnroll] = useState(null)
  const [qr, setQr] = useState('')
  const [busy, setBusy] = useState(false)
  const [ctxOpen, setCtxOpen] = useState(false)

  useEffect(() => { api.idpUsers().then(setMeta).catch((e) => setErr(e.message)) }, [])
  useEffect(() => { if (enroll?.otpauth) QRCode.toDataURL(enroll.otpauth, { margin: 1, width: 180, color: { dark: '#0a0a0b', light: '#ffffff' } }).then(setQr) }, [enroll])

  const users = (meta?.users || []).filter((u) => !u.disabled)
  const secret = users.find((u) => u.username === username)?.demoTotpSecret
  const loc = meta?.locations?.find((l) => l.key === form.location)

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

  async function submitPw(e) {
    e.preventDefault()
    setBusy(true); setErr('')
    try {
      let id = txn || await start(username)
      let r = await post(`${id}/password`, { ...form, username })
      if (r.status === 404 && start) { id = await start(username); r = await post(`${id}/password`, { ...form, username }) } // expired: start over once
      setTxn(id); handle(r)
    } catch (e2) { setBusy(false); setErr(e2.message || 'Could not start sign-in') }
  }
  const submitMFA = async (c = code) => { setBusy(true); handle(await post(`${txn}/mfa`, { code: c })) }
  const submitEnroll = async (c = code) => { setBusy(true); handle(await post(`${txn}/enroll`, { code: c })) }
  const restart = () => { setStep('password'); setErr(''); setEv(null); setCode(''); setEnroll(null); if (start) setTxn(null) }

  return (
    <div>
      {err && <div role="alert" className="mb-4 flex items-start gap-2 rounded-lg border border-rose-500/30 bg-rose-500/10 px-3 py-2 text-sm text-rose-300 animate-fade-in"><Lock className="mt-0.5 size-4 shrink-0" />{err}</div>}

      {step === 'password' && (
        <form onSubmit={submitPw} className="grid gap-y-4">
          <div>
            <label className="mb-2 block text-sm text-white" htmlFor="idp-u">Username</label>
            <input id="idp-u" className="input" autoComplete="username" required value={username} onChange={(e) => setUsername(e.target.value)} />
            <div className="mt-2 flex flex-wrap gap-1.5">
              {users.map((u) => (
                <button key={u.username} type="button" onClick={() => setUsername(u.username)}
                  className={`rounded-full px-2.5 py-1 text-xs ring-1 ring-inset transition ${username === u.username ? 'bg-violet-500/20 text-violet-100 ring-violet-500/40' : 'text-zinc-400 ring-white/10 hover:text-zinc-200'}`}>
                  {u.username}{u.breakGlass ? ' ⚠' : ''}<span className="ms-1 text-zinc-500">{roles[u.username] ? `· ${roles[u.username]}` : ''}{!u.mfaEnrolled ? ' · no MFA yet' : ''}</span>
                </button>
              ))}
            </div>
          </div>
          <div>
            <div className="mb-2 flex items-center justify-between">
              <label className="block text-sm text-white" htmlFor="idp-p">Password</label>
              {meta && <button type="button" className="text-xs font-medium text-violet-300 hover:underline" onClick={() => setForm({ ...form, password: meta.demoPassword })}>Use demo password</button>}
            </div>
            <div className="relative">
              <input id="idp-p" type={show ? 'text' : 'password'} className="input pe-10" autoComplete="current-password" required value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} />
              <button type="button" onClick={() => setShow(!show)} className="absolute inset-y-0 end-0 flex items-center px-3 text-zinc-500 hover:text-zinc-300" aria-label={show ? 'Hide password' : 'Show password'}>
                {show ? <EyeOff className="size-4" /> : <Eye className="size-4" />}
              </button>
            </div>
            <p className="mt-1.5 text-[11px] text-zinc-500">Five wrong tries trigger smart lockout.</p>
          </div>

          <div className="rounded-xl border border-white/[0.07] bg-white/[0.02]">
            <button type="button" onClick={() => setCtxOpen(!ctxOpen)} className="flex w-full items-center justify-between gap-2 px-3 py-2.5 text-start">
              <span className="text-xs font-semibold text-zinc-300">Simulate where you're signing in from</span>
              <span className="flex min-w-0 items-center gap-2 truncate text-[11px] text-zinc-500">{loc?.city} · {form.device}<ChevronDown className={`size-3.5 shrink-0 transition ${ctxOpen ? 'rotate-180' : ''}`} /></span>
            </button>
            {ctxOpen && meta && (
              <div className="space-y-3 border-t border-white/[0.06] p-3 animate-fade-in">
                <div>
                  <label className="label flex items-center gap-1.5"><MapPin className="size-3" /> Location / IP</label>
                  <select className="input" value={form.location} onChange={(e) => setForm({ ...form, location: e.target.value })}>
                    {meta.locations.map((l) => <option key={l.key} value={l.key}>{l.city}, {l.countryName} · {l.ip}</option>)}
                  </select>
                </div>
                <div className="flex flex-wrap gap-3">
                  <div><label className="label flex items-center gap-1.5"><Laptop className="size-3" /> Device</label><Seg value={form.device} onChange={(v) => setForm({ ...form, device: v })} options={['managed', 'unmanaged']} /></div>
                  <div><label className="label flex items-center gap-1.5"><Mail className="size-3" /> Client</label><Seg value={form.client} onChange={(v) => setForm({ ...form, client: v })} options={[{ value: 'browser', label: 'Browser' }, { value: 'legacy-imap', label: 'Legacy IMAP' }]} /></div>
                </div>
                <p className="text-[11px] leading-relaxed text-zinc-500">Conditional Access evaluates these signals. Try Moscow (geo-block), the Tor exit (high risk), an unmanaged device (step-up MFA) or legacy IMAP.</p>
              </div>
            )}
          </div>
          <Button type="submit" className="w-full py-3" disabled={busy || !username}>{busy ? 'Signing in…' : <>Sign in <ArrowRight className="size-4" /></>}</Button>
        </form>
      )}

      {step === 'mfa' && (
        <div className="space-y-4 animate-fade-up">
          <div className="flex items-center gap-2 text-sm text-zinc-200"><Smartphone className="size-4 text-violet-300" /> Enter the 6-digit code from your authenticator app</div>
          <CAEvalView ev={ev} compact />
          <input aria-label="One-time code" className="input text-center font-mono text-2xl tracking-[0.5em]" inputMode="numeric" maxLength={6} autoFocus value={code} onChange={(e) => setCode(e.target.value.replace(/\D/g, ''))} onKeyDown={(e) => e.key === 'Enter' && submitMFA()} />
          <Button className="w-full" disabled={busy || code.length !== 6} onClick={() => submitMFA()}>Verify</Button>
          {secret && <>
            <div className="eyebrow pt-2">Demo authenticator (stands in for the phone app)</div>
            <AuthenticatorTile label={`Assafwah IdP: ${username}`} secret={secret} onUse={(c) => { setCode(c); submitMFA(c) }} />
          </>}
          <button type="button" onClick={restart} className="w-full text-center text-xs text-zinc-500 hover:text-zinc-300">← Use a different account</button>
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
          <input aria-label="One-time code" className="input text-center font-mono text-2xl tracking-[0.5em]" inputMode="numeric" maxLength={6} value={code} onChange={(e) => setCode(e.target.value.replace(/\D/g, ''))} onKeyDown={(e) => e.key === 'Enter' && submitEnroll()} />
          <Button className="w-full" disabled={busy || code.length !== 6} onClick={() => submitEnroll()}>Confirm and continue</Button>
          <div className="eyebrow pt-2">No phone handy? Demo authenticator</div>
          <AuthenticatorTile label={`Assafwah IdP: ${username}`} secret={enroll.secret} onUse={(c) => { setCode(c); submitEnroll(c) }} />
        </div>
      )}

      {step === 'blocked' && (
        <div className="space-y-4 animate-fade-up">
          <div className="flex items-center gap-2 text-sm font-semibold text-rose-300"><ShieldX className="size-4" /> You can't get there from here</div>
          <p className="text-xs text-zinc-400">Conditional Access evaluated every policy below. One with a Block grant matched, so the sign-in stopped after the password step. It's in the sign-in log.</p>
          <CAEvalView ev={ev} />
          <Button variant="ghost" className="w-full" onClick={restart}>Try different conditions</Button>
        </div>
      )}

      {step === 'done' && (
        <div className="flex flex-col items-center gap-3 py-6 text-center animate-scale-in">
          <ShieldCheck className="size-10 text-emerald-400" />
          <div className="font-semibold text-white">Signed in</div>
          <div className="text-xs text-zinc-400">Exchanging the authorization code for tokens…</div>
          {ev && <Badge tone="ok">{ev.applied?.length ? `Policies applied: ${ev.applied.join(', ')}` : 'No policy required MFA'}</Badge>}
        </div>
      )}
    </div>
  )
}
