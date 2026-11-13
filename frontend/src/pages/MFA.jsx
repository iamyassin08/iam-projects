import { useEffect, useState } from 'react'
import { ShieldCheck, Smartphone, Ban, Users, Wand2, Lock, RotateCcw, X, MapPin } from 'lucide-react'
import { api, ago } from '../api.js'
import { useLoad, PageHeader, Card, Badge, Button, ErrorBox, Loading, Seg, toast, ask, Avatar, Stat, Field, usePreline } from '../ui.jsx'
import { CAEvalView, AuthenticatorTile, Flow } from '../components.jsx'

const condText = (p) => {
  const c = []
  if (p.clientApps?.length) c.push(`client: ${p.clientApps.join(', ')}`)
  if (p.countries?.length) c.push(`country in ${p.countries.join(', ')}`)
  if (p.notCountries?.length) c.push(`outside ${p.notCountries.join(', ')}`)
  if (p.blockedIps) c.push('IP on blocked list')
  if (p.riskLevels?.length) c.push(`risk ${p.riskLevels.join('/')}`)
  if (p.devices?.length) c.push(`device ${p.devices.join('/')}`)
  return c.length ? c.join(' · ') : 'any sign-in'
}

export default function MFA() {
  const [data, reload, error] = useLoad({ ca: api.ca, users: api.idpUsers })
  const [wi, setWi] = useState({ username: 'priya.raman', location: 'nashville', device: 'managed', client: 'browser' })
  const [ev, setEv] = useState(null)
  usePreline([data])

  useEffect(() => { api.whatIf(wi).then(setEv).catch(() => {}) }, [wi, data])

  async function setState(p, state) {
    if (state === p.state) return
    try { await api.setPolicy(p.id, state); await reload(); toast(`${p.id} → ${state}`) } catch (e) { toast(e.message, 'err') }
  }
  async function resetMFA(u) {
    const ok = await ask({ title: `Reset MFA for ${u.name}?`, message: 'Removes their authenticator. They must register a new one at next sign-in. Do this after a lost phone, or when an account may be compromised.', input: false, confirm: 'Reset MFA', tone: 'danger' })
    if (!ok) return
    try { await api.resetMFA(u.username); await reload(); toast('MFA reset; re-registration required') } catch (e) { toast(e.message, 'err') }
  }
  async function toggle(u) {
    try { await api.setUserDisabled(u.username, !u.disabled); await reload(); toast(u.disabled ? 'Sign-in allowed' : 'Sign-in blocked and sessions revoked') } catch (e) { toast(e.message, 'err') }
  }

  if (!data) return <><ErrorBox error={error} /><Loading /></>
  const { ca, users } = data
  const enrolled = users.users.filter((u) => u.mfaEnrolled).length
  const on = ca.policies.filter((p) => p.state === 'on').length

  return (
    <div className="space-y-6">
      <PageHeader icon={ShieldCheck} eyebrow="Project 4 · MFA, Conditional Access, zero trust · NIST IA-2(1)" title="MFA & Conditional Access"
        desc="Every sign-in to the built-in IdP runs through these policies, in the same model as Entra ID: assignments (who, which app), conditions (location, device, client app, sign-in risk) and a grant (block or require MFA). Policies can be On, Report-only or Off. Block beats MFA; MFA beats allow. Change a policy and the What-If panel and the real sign-in page change with it." />
      <ErrorBox error={error} />

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <Stat label="Users registered for MFA" value={enrolled} suffix={`/${users.users.length}`} icon={Smartphone} tone={enrolled === users.users.length ? 'ok' : 'warn'} />
        <Stat label="Policies enforced" value={on} suffix={`/${ca.policies.length}`} icon={ShieldCheck} tone="violet" delay={60} />
        <Stat label="Report-only policies" value={ca.policies.filter((p) => p.state === 'report-only').length} icon={Wand2} tone="info" delay={120} />
        <Stat label="Blocked IPs" value={ca.blockedIps.length} icon={Ban} tone={ca.blockedIps.length ? 'bad' : 'ok'} delay={180} />
      </div>

      <Card title="How a sign-in is decided" subtitle="The order the IdP evaluates things">
        <Flow nodes={[
          { title: 'Password', sub: 'PBKDF2-SHA256 hash · smart lockout after 5 failures' },
          { title: 'Signals', sub: 'user + groups, app, IP / country, device, client app' },
          { title: 'Sign-in risk', sub: 'anonymizer, blocked IP, new country, recent failures' },
          { title: 'Policies', sub: 'every On policy that applies; report-only only logs', tone: 'amber' },
          { title: 'Grant', sub: 'block > require MFA > allow', tone: 'emerald' },
        ]} />
      </Card>

      <Card title="Conditional Access policies" subtitle="Switch a policy and every sign-in from now on follows it" pad={false}>
        <ul className="divide-y divide-white/[0.06]">
          {ca.policies.map((p, i) => (
            <li key={p.id} className="flex flex-wrap items-center gap-4 px-5 py-3.5 animate-fade-up" style={{ animationDelay: `${i * 40}ms` }}>
              <div className="min-w-0 flex-1">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-mono text-xs text-zinc-500">{p.id}</span>
                  <span className="font-medium text-zinc-100">{p.name}</span>
                  <Badge tone={p.grant === 'block' ? 'bad' : 'warn'}>{p.grant === 'block' ? 'Block' : 'Require MFA'}</Badge>
                </div>
                <div className="mt-1 text-xs text-zinc-400">{p.description}</div>
                <div className="mt-1 flex flex-wrap gap-x-3 text-[11px] text-zinc-500">
                  <span>users: {p.includeGroups.join(', ')}{p.excludeGroups?.length ? ` (except ${p.excludeGroups.join(', ')})` : ''}</span>
                  <span>apps: {p.apps.join(', ')}</span>
                  <span>when: {condText(p)}</span>
                </div>
              </div>
              <Seg value={p.state} onChange={(v) => setState(p, v)} options={[{ value: 'on', label: 'On' }, { value: 'report-only', label: 'Report-only' }, { value: 'off', label: 'Off' }]} />
            </li>
          ))}
        </ul>
      </Card>

      <div className="grid gap-6 lg:grid-cols-5">
        <Card className="lg:col-span-2" title="What If" subtitle="Test a sign-in without signing in (like Entra's What If tool)">
          <div className="space-y-3">
            <Field label="User">
              <select className="input" value={wi.username} onChange={(e) => setWi({ ...wi, username: e.target.value })}>
                {users.users.map((u) => <option key={u.username} value={u.username}>{u.name} ({u.groups.join(', ')})</option>)}
              </select>
            </Field>
            <Field label="Location">
              <select className="input" value={wi.location} onChange={(e) => setWi({ ...wi, location: e.target.value })}>
                {ca.locations.map((l) => <option key={l.key} value={l.key}>{l.city}, {l.countryName}{l.anonymizer ? ' (anonymizer)' : ''}</option>)}
              </select>
            </Field>
            <div className="flex flex-wrap gap-3">
              <Field label="Device"><Seg value={wi.device} onChange={(v) => setWi({ ...wi, device: v })} options={['managed', 'unmanaged']} /></Field>
              <Field label="Client app"><Seg value={wi.client} onChange={(v) => setWi({ ...wi, client: v })} options={[{ value: 'browser', label: 'Browser' }, { value: 'legacy-imap', label: 'Legacy' }]} /></Field>
            </div>
          </div>
        </Card>
        <Card className="lg:col-span-3" title="Result" subtitle="Every policy, whether it applied, and why">
          <CAEvalView ev={ev} />
        </Card>
      </div>

      <div className="grid gap-6 lg:grid-cols-5">
        <Card className="lg:col-span-3" title="MFA registration" subtitle="Directory users of the built-in IdP" pad={false}>
          <div className="overflow-x-auto">
            <table className="min-w-full">
              <thead><tr><th className="th">User</th><th className="th">Groups</th><th className="th">MFA</th><th className="th">Status</th><th className="th">Last sign-in</th><th className="th" /></tr></thead>
              <tbody>
                {users.users.map((u) => (
                  <tr key={u.username} className="row">
                    <td className="td"><div className="flex items-center gap-2"><Avatar name={u.name} size="size-7" /><div><div className="text-zinc-100">{u.name}</div><div className="font-mono text-[11px] text-zinc-500">{u.username}</div></div></div></td>
                    <td className="td"><div className="flex flex-wrap gap-1">{u.groups.map((g) => <Badge key={g} tone={g === 'break-glass' ? 'bad' : g === 'iam-admins' ? 'violet' : 'neutral'}>{g}</Badge>)}</div></td>
                    <td className="td">{u.mfaEnrolled ? <Badge tone="ok" dot>{u.mfaMethod || 'totp'}</Badge> : <Badge tone="warn" dot>not registered</Badge>}</td>
                    <td className="td">{u.disabled ? <Badge tone="bad">blocked</Badge> : u.lockedUntil ? <Badge tone="warn"><Lock className="size-3" /> locked</Badge> : <Badge tone="ok">enabled</Badge>}</td>
                    <td className="td text-xs text-zinc-400">{ago(u.lastSignIn)}</td>
                    <td className="td whitespace-nowrap text-end">
                      {u.mfaEnrolled && <Button size="sm" variant="subtle" onClick={() => resetMFA(u)}><RotateCcw className="size-3.5" /> Reset MFA</Button>}
                      <Button size="sm" variant="subtle" onClick={() => toggle(u)}>{u.disabled ? 'Unblock' : 'Block sign-in'}</Button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <p className="px-5 py-3 text-xs text-zinc-500">The break-glass account is excluded from every policy except the IP block, so a broken policy can't lock everyone out. Its use always raises a critical alert.</p>
        </Card>
        <Card className="lg:col-span-2" title="Demo authenticator" subtitle={`Live TOTP codes (RFC 6238). Password for everyone: ${users.demoPassword}`}>
          <div className="space-y-2">
            {users.users.filter((u) => u.demoTotpSecret).map((u) => <AuthenticatorTile key={u.username} label={`${u.name} · ${u.username}`} secret={u.demoTotpSecret} />)}
          </div>
          <p className="mt-3 text-[11px] leading-relaxed text-zinc-500">A real IdP never exposes these secrets. They are shown only so visitors without the phone app can finish an MFA sign-in. Same HMAC-SHA1, 30-second, 6-digit algorithm as Microsoft and Google Authenticator.</p>
        </Card>
      </div>

      <Card title="Blocked IPs (named location used by CA006)" subtitle="Added from identity threat alerts with the Block IP response">
        {ca.blockedIps.length === 0 ? <p className="flex items-center gap-2 text-sm text-zinc-500"><MapPin className="size-4" />Nothing blocked yet. Triage the password-spray alert on Identity threat detection and choose Block IP.</p> : (
          <div className="flex flex-wrap gap-2">
            {ca.blockedIps.map((ip) => (
              <span key={ip} className="inline-flex items-center gap-2 rounded-lg border border-rose-500/30 bg-rose-500/10 px-2.5 py-1 font-mono text-xs text-rose-200">
                {ip}<button type="button" aria-label={`Unblock ${ip}`} onClick={async () => { await api.unblockIP(ip); reload() }} className="text-rose-300 hover:text-white"><X className="size-3.5" /></button>
              </span>
            ))}
          </div>
        )}
      </Card>
    </div>
  )
}
