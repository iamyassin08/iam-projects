import { useMemo, useState } from 'react'
import { Vault as VaultIcon, KeyRound, LockKeyhole, RefreshCw, Eye, EyeOff, Copy, Timer, ShieldCheck } from 'lucide-react'
import { api, ago, until } from '../api.js'
import { makeLookups } from '../lookups.js'
import { useLoad, PageHeader, Card, Badge, Button, ErrorBox, Loading, toast, ask, Modal, Field, openModal, closeModal, Stat, useTick, usePreline } from '../ui.jsx'
import { AuthenticatorTile, Flow } from '../components.jsx'

export default function Vault() {
  const [data, reload, error] = useLoad({ vault: api.vault, catalog: api.catalog, people: api.identities, users: api.idpUsers, pam: api.pam }, [], { poll: 15000 })
  const [sel, setSel] = useState(null)
  const [form, setForm] = useState({ identityId: 'ID-7', reason: '', code: '' })
  const [revealed, setRevealed] = useState(null)
  const [show, setShow] = useState(false)
  const L = useMemo(() => makeLookups(data?.catalog, data?.people), [data])
  useTick(1000)
  usePreline([data])

  function start(v) {
    setSel(v)
    setForm({ identityId: 'ID-7', reason: '', code: '' })
    openModal('vault-checkout')
  }
  async function checkout() {
    try {
      const r = await api.checkout(sel.id, form)
      setRevealed({ ...r, name: sel.name, account: sel.account })
      setShow(false)
      closeModal('vault-checkout')
      setTimeout(() => openModal('vault-reveal'), 250)
      reload()
    } catch (e) { toast(e.message, 'err') }
  }
  async function checkin(v) {
    try { await api.checkin(v.id); await reload(); toast(`${v.name} checked in and rotated`) } catch (e) { toast(e.message, 'err') }
  }
  async function rotate(v) {
    const ok = await ask({ title: `Rotate ${v.name}?`, message: 'Generates a new 24-character password, re-encrypts it and pushes it to the target account.', input: false, confirm: 'Rotate' })
    if (!ok) return
    try { await api.rotate(v.id); await reload(); toast('Rotated') } catch (e) { toast(e.message, 'err') }
  }

  if (!data) return <><ErrorBox error={error} /><Loading /></>
  const { vault, users, pam } = data
  const mapUser = Object.fromEntries(users.users.filter((u) => u.identityId).map((u) => [u.identityId, u]))
  const active = pam.sessions?.filter((s) => s.status === 'active') || []
  const who = mapUser[form.identityId]

  return (
    <div className="space-y-6">
      <PageHeader icon={VaultIcon} eyebrow="Project 5 · privileged access management · NIST AC-2(4), IA-5(1), CIS 5.2" title="Credential vault"
        desc="The PAM half of privileged access, like CyberArk or Delinea. Shared admin passwords are encrypted with AES-256-GCM and never listed. To check one out you must hold the matching privileged access right now (usually a just-in-time elevation), give a reason, and pass step-up MFA. Checkouts last 30 minutes and the password rotates automatically at check-in or expiry, so a copied password stops working." />
      <ErrorBox error={error} />

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <Stat label="Vaulted credentials" value={vault.length} icon={LockKeyhole} />
        <Stat label="Checked out now" value={vault.filter((v) => v.checkedOutBy).length} icon={Timer} tone="info" delay={60} />
        <Stat label="Overdue rotation" value={vault.filter((v) => v.overdue).length} icon={RefreshCw} tone={vault.some((v) => v.overdue) ? 'bad' : 'ok'} delay={120} />
        <Stat label="Live JIT elevations" value={active.length} icon={ShieldCheck} tone="violet" delay={180} />
      </div>

      <Card title="Checkout workflow" subtitle="Four gates between a person and an admin password">
        <Flow nodes={[
          { title: 'JIT elevation', sub: 'eligible, ticket, time-boxed (Just-in-time access page)' },
          { title: 'Reason', sub: 'written to the audit log' },
          { title: 'Step-up MFA', sub: 'fresh TOTP, even if already signed in', tone: 'amber' },
          { title: '30-min checkout', sub: 'exclusive: one holder at a time' },
          { title: 'Auto-rotate', sub: 'on check-in or expiry', tone: 'emerald' },
        ]} />
      </Card>

      <Card title="Vaulted accounts" subtitle="Passwords are never shown here, only a ciphertext fingerprint" pad={false}>
        <div className="overflow-x-auto">
          <table className="min-w-full">
            <thead><tr><th className="th">Credential</th><th className="th">Requires</th><th className="th">Version</th><th className="th">Last rotated</th><th className="th">Status</th><th className="th" /></tr></thead>
            <tbody>
              {vault.map((v) => (
                <tr key={v.id} className="row">
                  <td className="td"><div className="font-medium text-zinc-100">{v.name}</div><div className="font-mono text-[11px] text-zinc-500">{v.account} · {L.sys[v.systemId]?.name} · {v.fingerprint}</div></td>
                  <td className="td"><Badge tone="warn">{L.entName(v.entitlementId)}</Badge></td>
                  <td className="td font-mono text-xs text-zinc-300">v{v.version} · {v.checkouts} checkouts</td>
                  <td className="td text-xs">{v.overdue ? <Badge tone="bad">{v.ageDays}d ago (policy {v.rotationDays}d)</Badge> : <span className="text-zinc-400">{ago(v.rotatedAt)}</span>}</td>
                  <td className="td">{v.checkedOutBy ? <div><Badge tone="info" dot>checked out</Badge><div className="mt-1 text-[11px] text-zinc-500">{v.checkedOutBy} · {until(v.checkoutExpires)} left</div></div> : <Badge tone="ok" dot>in vault</Badge>}</td>
                  <td className="td whitespace-nowrap text-end">
                    {v.checkedOutBy ? <Button size="sm" variant="ghost" onClick={() => checkin(v)}>Check in</Button> : <Button size="sm" onClick={() => start(v)}><KeyRound className="size-3.5" /> Check out</Button>}
                    <Button size="sm" variant="subtle" onClick={() => rotate(v)}><RefreshCw className="size-3.5" /> Rotate</Button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>

      <Modal id="vault-checkout" title={`Check out ${sel?.name || ''}`} size="md"
        footer={<><Button variant="ghost" data-hs-overlay="#vault-checkout">Cancel</Button><Button onClick={checkout} disabled={!form.reason || form.code.length !== 6}>Verify and check out</Button></>}>
        <div className="space-y-4">
          <Field label="Who is checking out" hint="Must hold this access now. Yusuf can activate ServiceNow admin or Domain Admins on the Just-in-time access page.">
            <select className="input" value={form.identityId} onChange={(e) => setForm({ ...form, identityId: e.target.value, code: '' })}>
              {data.people.filter((p) => p.status === 'active').map((p) => <option key={p.id} value={p.id}>{p.name}{mapUser[p.id] ? '' : ' (no MFA method)'}</option>)}
            </select>
          </Field>
          {sel && <div className="flex flex-wrap gap-2 text-xs">
            {active.some((s) => s.identityId === form.identityId && s.entitlementId === sel.entitlementId)
              ? <Badge tone="ok" dot>Active JIT elevation for {L.entName(sel.entitlementId)}</Badge>
              : <Badge tone="warn" dot>No live elevation for {L.entName(sel.entitlementId)} (standing grants also count)</Badge>}
          </div>}
          <Field label="Reason" required><input className="input" value={form.reason} placeholder="CHG0012345: rotate the SCIM connector secret" onChange={(e) => setForm({ ...form, reason: e.target.value })} /></Field>
          <Field label="Step-up MFA code" required>
            <input className="input text-center font-mono text-xl tracking-[0.4em]" maxLength={6} inputMode="numeric" value={form.code} onChange={(e) => setForm({ ...form, code: e.target.value.replace(/\D/g, '') })} />
          </Field>
          {who?.demoTotpSecret && <AuthenticatorTile label={`Demo authenticator: ${who.username}`} secret={who.demoTotpSecret} onUse={(c) => setForm((f) => ({ ...f, code: c }))} />}
        </div>
      </Modal>

      <Modal id="vault-reveal" title={`${revealed?.name || ''}`} size="md" footer={<Button data-hs-overlay="#vault-reveal">Done</Button>}>
        {revealed && <div className="space-y-3">
          <div className="text-xs text-zinc-400">Account <span className="code">{revealed.account}</span></div>
          <div className="flex items-center gap-2 rounded-xl border border-emerald-500/30 bg-emerald-500/10 p-3">
            <code className="flex-1 break-all font-mono text-sm text-emerald-100">{show ? revealed.password : '•'.repeat(24)}</code>
            <button type="button" aria-label="Show" onClick={() => setShow(!show)} className="text-zinc-300 hover:text-white">{show ? <EyeOff className="size-4" /> : <Eye className="size-4" />}</button>
            <button type="button" aria-label="Copy" onClick={() => { navigator.clipboard?.writeText(revealed.password); toast('Copied. It rotates at check-in.') }} className="text-zinc-300 hover:text-white"><Copy className="size-4" /></button>
          </div>
          <p className="text-xs text-zinc-400">{revealed.note} Expires {until(revealed.expiresAt)} from now.</p>
        </div>}
      </Modal>
    </div>
  )
}
