import { useEffect, useRef, useState } from 'react'
import { UserRound, Camera, Trash2, Save, ShieldCheck, KeyRound, Activity, Settings2, Download, LogOut, RotateCcw, LogIn, Smartphone, Building2, Mail, MapPin, Globe, Clock, AlertTriangle, CheckCircle2 } from 'lucide-react'
import { api, ago, fmtDate, downloadFile } from '../api.js'
import { PageHeader, Card, Badge, Button, ErrorBox, Loading, Seg, Field, toast, ask, Empty } from '../ui.jsx'
import { refreshMe } from '../me.js'
import { UserAvatar } from '../components.jsx'
import { NAV } from '../App.jsx'

const TABS = [
  { value: 'profile', label: 'Profile' },
  { value: 'access', label: 'My access' },
  { value: 'security', label: 'Security' },
  { value: 'activity', label: 'Activity' },
  { value: 'preferences', label: 'Preferences' },
]
const ZONES = ['America/Chicago', 'America/New_York', 'America/Denver', 'America/Los_Angeles', 'Europe/London', 'Europe/Berlin', 'Africa/Nairobi', 'Asia/Dubai', 'Asia/Kolkata', 'UTC']

// Resize any picked image to a 192px square JPEG so avatars stay small.
function toAvatar(file) {
  return new Promise((resolve, reject) => {
    if (!/^image\/(png|jpeg|webp|gif)$/.test(file.type)) return reject(new Error('Choose a PNG, JPEG, WebP or GIF image'))
    if (file.size > 8 * 1024 * 1024) return reject(new Error('That image is over 8 MB'))
    const img = new Image()
    img.onload = () => {
      const size = 192, c = document.createElement('canvas')
      c.width = c.height = size
      const s = Math.min(img.width, img.height)
      c.getContext('2d').drawImage(img, (img.width - s) / 2, (img.height - s) / 2, s, s, 0, 0, size, size)
      URL.revokeObjectURL(img.src)
      resolve(c.toDataURL('image/jpeg', 0.85))
    }
    img.onerror = () => reject(new Error('Could not read that image'))
    img.src = URL.createObjectURL(file)
  })
}

export default function Profile() {
  const tabFromHash = () => new URLSearchParams(window.location.hash.split('?')[1] || '').get('tab') || 'profile'
  const [tab, setTab] = useState(tabFromHash)
  const [data, setData] = useState(null)
  const [form, setForm] = useState(null)
  const [error, setError] = useState('')
  const [unauth, setUnauth] = useState(false)
  const [busy, setBusy] = useState(false)
  const fileRef = useRef(null)

  async function load() {
    try {
      const d = await api.profile()
      setData(d)
      setForm({ ...d.profile, prefs: { landing: '', reduceMotion: false, collapsed: false, ...d.profile.prefs } })
      setUnauth(false)
    } catch (e) {
      if (/sign in/i.test(e.message)) setUnauth(true)
      else setError(e.message)
    }
  }
  useEffect(() => { load() }, [])
  useEffect(() => { const on = () => setTab(tabFromHash()); window.addEventListener('hashchange', on); return () => window.removeEventListener('hashchange', on) }, [])

  function go(t) { setTab(t); history.replaceState(null, '', `#profile${t === 'profile' ? '' : `?tab=${t}`}`) }

  async function save(next = form, msg = 'Profile saved') {
    setBusy(true)
    try {
      const d = await api.saveProfile(next)
      setData(d)
      setForm({ ...d.profile, prefs: { landing: '', reduceMotion: false, collapsed: false, ...d.profile.prefs } })
      if (next.prefs?.collapsed !== undefined) {
        try { localStorage.setItem('iam.sidebar', next.prefs.collapsed ? 'collapsed' : 'open') } catch { /* private mode */ }
        window.dispatchEvent(new Event('iam:sidebar'))
      }
      await refreshMe()
      toast(msg)
    } catch (e) { toast(e.message, 'err') }
    setBusy(false)
  }
  async function pickAvatar(e) {
    const f = e.target.files?.[0]
    e.target.value = ''
    if (!f) return
    try { const avatar = await toAvatar(f); await save({ ...form, avatar }, 'Avatar updated') } catch (err) { toast(err.message, 'err') }
  }
  async function resetAll() {
    const ok = await ask({ title: 'Reset your profile?', message: 'Removes your avatar, details and preferences. Your account, access and history are not affected.', input: false, confirm: 'Reset', tone: 'danger' })
    if (!ok) return
    await api.resetProfile(); await load(); await refreshMe(); toast('Profile reset')
  }
  async function everywhere() {
    const ok = await ask({ title: 'Sign out everywhere?', message: 'Ends every session for this account, on every device, including this one. You will need to sign in again.', input: false, confirm: 'Sign out everywhere', tone: 'danger' })
    if (!ok) return
    await api.signOutEverywhere(); window.location.hash = 'login'; await refreshMe()
  }
  async function resetMFA() {
    const ok = await ask({ title: 'Reset your MFA?', message: 'Removes your authenticator. At your next sign-in you will scan a new QR code. Do this if you lost or replaced your phone.', input: false, confirm: 'Reset MFA', tone: 'danger' })
    if (!ok) return
    try { await api.resetMyMFA(); await load(); toast('MFA reset. You will enrol again at next sign-in.') } catch (e) { toast(e.message, 'err') }
  }
  function exportData() { downloadFile(`${data.account.username}-data.json`, JSON.stringify(data, null, 2), 'application/json'); toast('Your data was downloaded') }

  if (unauth) return (
    <div className="space-y-6">
      <PageHeader icon={UserRound} eyebrow="Self-service" title="My profile" desc="Your profile, access, security settings and activity live here once you sign in." />
      <Card>
        <div className="flex flex-col items-center gap-3 py-10 text-center">
          <span className="inline-flex size-14 items-center justify-center rounded-2xl bg-violet-500/15 ring-1 ring-violet-500/30"><LogIn className="size-6 text-violet-300" /></span>
          <div className="text-lg font-semibold text-white">Sign in to see your profile</div>
          <p className="max-w-md text-sm text-zinc-400">Use any demo account (password <span className="code">test123</span>) through the built-in IdP or Keycloak.</p>
          <a href="#login"><Button><LogIn className="size-4" /> Sign in</Button></a>
        </div>
      </Card>
    </div>
  )
  if (!data || !form) return <><ErrorBox error={error} /><Loading /></>
  const { account: a, access, signIns, actions } = data
  const id = a.identity
  const meLike = { profile: { ...form }, user: { n: a.name, u: a.username } }
  const dirty = JSON.stringify({ ...data.profile, prefs: { landing: '', reduceMotion: false, collapsed: false, ...data.profile.prefs } }) !== JSON.stringify(form)
  const hasMFA = (a.amr || []).some((x) => x === 'mfa' || x === 'otp')
  const pages = NAV.flatMap((g) => g.items).filter((i) => i.id !== 'profile')

  return (
    <div className="space-y-6">
      {/* header card */}
      <section className="relative overflow-hidden rounded-3xl border border-white/[0.07] bg-gradient-to-br from-violet-950/60 via-zinc-900/60 to-zinc-950 p-6 sm:p-8 animate-fade-up">
        <div aria-hidden className="absolute -end-16 -top-16 size-64 rounded-full bg-violet-500/20 blur-3xl" />
        <div className="relative flex flex-wrap items-center gap-5">
          <div className="group relative">
            <UserAvatar me={meLike} size="size-24" text="text-2xl" />
            <button type="button" onClick={() => fileRef.current?.click()} aria-label="Change avatar"
              className="absolute inset-0 flex items-center justify-center rounded-full bg-black/55 text-white opacity-0 transition group-hover:opacity-100 focus:opacity-100"><Camera className="size-6" /></button>
            <input ref={fileRef} type="file" accept="image/png,image/jpeg,image/webp,image/gif" className="hidden" onChange={pickAvatar} />
          </div>
          <div className="min-w-0 flex-1">
            <h1 className="font-display text-2xl font-bold text-white sm:text-3xl">{form.displayName || a.name}</h1>
            <div className="mt-1 text-sm text-zinc-300">{form.title || id?.title || 'No title yet'}{id?.department ? ` · ${id.department}` : ''}</div>
            <div className="mt-2 flex flex-wrap gap-1.5">
              <Badge tone="info">{a.idp === 'keycloak' ? 'Keycloak' : 'Built-in IdP'}</Badge>
              {a.admin && <Badge tone="violet">Admin</Badge>}
              {hasMFA ? <Badge tone="ok">Signed in with MFA</Badge> : <Badge tone="warn">Signed in without MFA</Badge>}
              {a.builtIn && (a.mfaEnrolled ? <Badge tone="ok">Authenticator registered</Badge> : <Badge tone="warn">No authenticator</Badge>)}
              {id && <Badge tone={id.status === 'active' ? 'ok' : 'bad'}>HR: {id.status}</Badge>}
            </div>
          </div>
          <div className="flex flex-wrap gap-2">
            <Button variant="ghost" onClick={() => fileRef.current?.click()}><Camera className="size-4" /> {form.avatar ? 'Change photo' : 'Add photo'}</Button>
            {form.avatar && <Button variant="subtle" onClick={() => save({ ...form, avatar: '' }, 'Photo removed')}><Trash2 className="size-4" /></Button>}
          </div>
        </div>
      </section>

      <div className="overflow-x-auto"><Seg value={tab} onChange={go} options={TABS} /></div>

      {tab === 'profile' && (
        <div className="grid gap-6 lg:grid-cols-5">
          <Card className="lg:col-span-3" title="Edit profile" subtitle="Shown in the top bar and on your audit trail views"
            actions={<Button size="sm" onClick={() => save()} disabled={!dirty || busy}><Save className="size-3.5" /> Save changes</Button>}>
            <div className="grid gap-4 sm:grid-cols-2">
              <Field label="Display name"><input className="input" maxLength={60} value={form.displayName} placeholder={a.name} onChange={(e) => setForm({ ...form, displayName: e.target.value })} /></Field>
              <Field label="Job title"><input className="input" maxLength={80} value={form.title} placeholder={id?.title || 'IAM Analyst'} onChange={(e) => setForm({ ...form, title: e.target.value })} /></Field>
              <Field label="Location"><input className="input" maxLength={60} value={form.location} placeholder="Nashville, TN" onChange={(e) => setForm({ ...form, location: e.target.value })} /></Field>
              <Field label="Time zone"><select className="input" value={form.timezone} onChange={(e) => setForm({ ...form, timezone: e.target.value })}>{ZONES.map((z) => <option key={z}>{z}</option>)}</select></Field>
              <div className="sm:col-span-2"><Field label="Website" hint="LinkedIn, GitHub or portfolio (https only)"><input className="input" maxLength={120} value={form.website} placeholder="https://www.linkedin.com/in/…" onChange={(e) => setForm({ ...form, website: e.target.value })} /></Field></div>
              <div className="sm:col-span-2"><Field label="About" hint={`${form.bio.length}/400`}><textarea className="input" rows={4} maxLength={400} value={form.bio} placeholder="What you work on" onChange={(e) => setForm({ ...form, bio: e.target.value })} /></Field></div>
            </div>
            {dirty && <p className="mt-3 text-xs text-amber-300">You have unsaved changes.</p>}
          </Card>
          <Card className="lg:col-span-2" title="From your identity provider" subtitle="Managed centrally; change these in HR or the IdP, not here">
            <dl className="space-y-3 text-sm">
              {[[UserRound, 'Username', a.username], [Mail, 'Email', a.email], [Building2, 'Department', id?.department], [UserRound, 'Manager', id?.manager], [KeyRound, 'Role', id?.role], [Clock, 'Start date', id?.startDate], [MapPin, 'Location', form.location], [Globe, 'Website', form.website]].filter(([, , v]) => v).map(([I, k, v]) => (
                <div key={k} className="flex items-start gap-3"><I className="mt-0.5 size-4 text-zinc-500" /><dt className="w-24 shrink-0 text-zinc-500">{k}</dt><dd className="min-w-0 break-words text-zinc-200">{k === 'Website' ? <a href={v} target="_blank" rel="noreferrer noopener" className="text-violet-300 hover:underline">{v.replace('https://', '')}</a> : v}</dd></div>
              ))}
            </dl>
            <div className="mt-4 flex flex-wrap gap-1.5">{a.groups.map((g) => <Badge key={g} tone={g.includes('admin') ? 'violet' : 'neutral'}>{g}</Badge>)}</div>
          </Card>
        </div>
      )}

      {tab === 'access' && (
        <Card title="What I can access" subtitle={id ? `${access.length} entitlements via role ${id.role}, requests and just-in-time elevation` : 'This account is not linked to an HR identity'} pad={false}
          actions={<><a href="#requests"><Button size="sm" variant="ghost">Request access</Button></a><a href="#pam"><Button size="sm" variant="ghost">Activate admin (JIT)</Button></a></>}>
          {access.length === 0 ? <Empty icon={KeyRound}>No access is granted to this account.</Empty> : (
            <div className="overflow-x-auto">
              <table className="min-w-full">
                <thead><tr><th className="th">System</th><th className="th">Entitlement</th><th className="th">How I got it</th><th className="th">Last used</th></tr></thead>
                <tbody>{access.map((g) => (
                  <tr key={g.entitlementId} className="row">
                    <td className="td text-zinc-300">{g.system}</td>
                    <td className="td"><span className="text-zinc-100">{g.name}</span>{g.privileged && <Badge tone="warn" className="ms-2">privileged</Badge>}</td>
                    <td className="td"><Badge tone={g.source === 'role' ? 'neutral' : g.source === 'jit' ? 'info' : 'violet'}>{g.source === 'role' ? 'birthright (role)' : g.source === 'jit' ? 'just-in-time' : 'approved request'}</Badge>{g.expiresAt && <div className="mt-1 text-[11px] text-zinc-500">expires {fmtDate(g.expiresAt)}</div>}</td>
                    <td className="td text-xs text-zinc-400">{ago(g.lastUsed)}</td>
                  </tr>
                ))}</tbody>
              </table>
            </div>
          )}
        </Card>
      )}

      {tab === 'security' && (
        <div className="grid gap-6 lg:grid-cols-2">
          <Card title="Sign-in & MFA">
            <ul className="space-y-3 text-sm">
              <li className="flex items-center justify-between gap-3"><span className="flex items-center gap-2 text-zinc-300"><Building2 className="size-4 text-zinc-500" />Identity provider</span><span className="text-zinc-100">{a.idp === 'keycloak' ? 'Keycloak (keycloak.assafwahinc.com)' : 'Assafwah IdP (built-in)'}</span></li>
              <li className="flex items-center justify-between gap-3"><span className="flex items-center gap-2 text-zinc-300"><ShieldCheck className="size-4 text-zinc-500" />This session</span>{hasMFA ? <Badge tone="ok">password + one-time code</Badge> : <Badge tone="warn">password only</Badge>}</li>
              {a.builtIn && <li className="flex items-center justify-between gap-3"><span className="flex items-center gap-2 text-zinc-300"><Smartphone className="size-4 text-zinc-500" />Authenticator app</span>{a.mfaEnrolled ? <Badge tone="ok">registered ({a.mfaMethod || 'totp'})</Badge> : <Badge tone="warn">not registered</Badge>}</li>}
              {a.lastSignIn && <li className="flex items-center justify-between gap-3"><span className="flex items-center gap-2 text-zinc-300"><Clock className="size-4 text-zinc-500" />Last sign-in</span><span className="text-zinc-100">{ago(a.lastSignIn)}</span></li>}
            </ul>
            {!hasMFA && <div className="mt-4 flex gap-2 rounded-xl border border-amber-500/25 bg-amber-500/10 p-3 text-xs text-amber-200"><AlertTriangle className="size-4 shrink-0" />You signed in without MFA because "Require MFA for all users" (CA002) is only in report-only. Switch it on in MFA &amp; Conditional Access to close this gap.</div>}
            <div className="mt-4 flex flex-wrap gap-2">
              {a.builtIn ? <Button variant="ghost" onClick={resetMFA}><RotateCcw className="size-4" /> Reset my MFA</Button>
                : <a href="https://keycloak.assafwahinc.com/realms/assafwah/account" target="_blank" rel="noreferrer"><Button variant="ghost"><ShieldCheck className="size-4" /> Keycloak account console</Button></a>}
              <a href="#sso"><Button variant="subtle">View my tokens</Button></a>
            </div>
          </Card>
          <Card title="Sessions">
            <p className="text-sm text-zinc-400">Lost a device or used a shared computer? End every session for this account at once. Admins can do the same from an identity alert.</p>
            <div className="mt-4 flex flex-wrap gap-2">
              <Button variant="danger" onClick={everywhere}><LogOut className="size-4" /> Sign out everywhere</Button>
            </div>
            <p className="mt-4 text-xs text-zinc-500">Sessions last 8 hours. Signing out everywhere invalidates every session cookie issued before now (the same control an analyst uses after impossible travel or MFA fatigue).</p>
          </Card>
        </div>
      )}

      {tab === 'activity' && (
        <div className="grid gap-6 lg:grid-cols-2">
          <Card title="My recent sign-ins" pad={false}>
            {signIns.length === 0 ? <Empty icon={Activity}>No sign-ins recorded for this username.</Empty> : (
              <ul className="divide-y divide-white/[0.06]">{signIns.map((s) => (
                <li key={s.id} className="flex items-center gap-3 px-5 py-3 text-sm">
                  {s.result === 'success' ? <CheckCircle2 className="size-4 text-emerald-400" /> : <AlertTriangle className="size-4 text-rose-400" />}
                  <div className="min-w-0 flex-1"><div className="text-zinc-200">{s.city}, {s.country} · {s.app}</div><div className="text-xs text-zinc-500">{fmtDate(s.at)} · {s.client} · MFA {s.mfa}</div></div>
                  <Badge tone={s.result === 'success' ? 'ok' : 'bad'}>{s.result}</Badge>
                </li>
              ))}</ul>
            )}
            <p className="px-5 py-3 text-xs text-zinc-500">Don't recognise one? Sign out everywhere and reset your MFA.</p>
          </Card>
          <Card title="What I did" subtitle="Audit-log entries recorded under your name" pad={false}>
            {actions.length === 0 ? <Empty icon={Activity}>Nothing yet. Approve a request or change a policy and it shows up here.</Empty> : (
              <ul className="divide-y divide-white/[0.06]">{actions.map((x) => (
                <li key={x.id} className="px-5 py-3 text-sm"><div className="flex items-center justify-between gap-2"><span className="font-mono text-xs text-violet-300">{x.action}</span><span className="text-xs text-zinc-500">{ago(x.at)}</span></div><div className="mt-0.5 text-zinc-300">{x.detail}</div></li>
              ))}</ul>
            )}
          </Card>
        </div>
      )}

      {tab === 'preferences' && (
        <div className="grid gap-6 lg:grid-cols-2">
          <Card title="Preferences" subtitle="Saved to your profile, so they follow you to other browsers">
            <div className="space-y-4">
              <Field label="Open this page when I arrive">
                <select className="input" value={form.prefs.landing} onChange={(e) => setForm({ ...form, prefs: { ...form.prefs, landing: e.target.value } })}>
                  <option value="">Security posture (default)</option>
                  {pages.filter((p) => p.id !== 'home').map((p) => <option key={p.id} value={p.id}>{p.label}</option>)}
                </select>
              </Field>
              {[['reduceMotion', 'Reduce motion', 'Turn off animations and transitions'], ['collapsed', 'Compact sidebar', 'Start with the sidebar collapsed to icons']].map(([k, t, d]) => (
                <label key={k} className="flex cursor-pointer items-start justify-between gap-4 rounded-xl border border-white/[0.06] p-3">
                  <span><span className="block text-sm font-medium text-zinc-100">{t}</span><span className="text-xs text-zinc-500">{d}</span></span>
                  <input type="checkbox" className="mt-1 size-4 rounded border-white/20 bg-zinc-900 text-violet-600" checked={!!form.prefs[k]} onChange={(e) => setForm({ ...form, prefs: { ...form.prefs, [k]: e.target.checked } })} />
                </label>
              ))}
              <Button onClick={() => save(form, 'Preferences saved')} disabled={!dirty || busy}><Save className="size-4" /> Save preferences</Button>
            </div>
          </Card>
          <Card title="Your data">
            <p className="text-sm text-zinc-400">Download everything this app holds about your account (profile, access, sign-ins, actions), or wipe your profile customisations.</p>
            <div className="mt-4 flex flex-wrap gap-2">
              <Button variant="ghost" onClick={exportData}><Download className="size-4" /> Download my data</Button>
              <Button variant="subtle" onClick={resetAll}><Trash2 className="size-4" /> Reset my profile</Button>
            </div>
            <p className="mt-4 text-xs text-zinc-500">Demo accounts are shared by every visitor, and Reset demo clears all profiles. Don't put real personal information here.</p>
          </Card>
        </div>
      )}
    </div>
  )
}
