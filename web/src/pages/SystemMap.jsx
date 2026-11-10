import { Network, Database, Fingerprint, FolderTree, AppWindow, Cloud, ChevronRight, AlertTriangle } from 'lucide-react'
import { api } from '../api.js'
import { useLoad, PageHeader, Card, Badge, ErrorBox, Loading, usePreline, Tooltip } from '../ui.jsx'

const TIERS = [
  { cat: 'hris', label: 'HR source of truth', icon: Database, note: 'Authoritative for who works here' },
  { cat: 'idp', label: 'Identity provider', icon: Fingerprint, note: 'SSO + SCIM push downstream' },
  { cat: 'directory', label: 'Directory', icon: FolderTree, note: 'Kerberos / LDAP for on-prem' },
  { cat: 'app', label: 'Applications', icon: AppWindow, note: 'Federated via SAML' },
  { cat: 'cloud', label: 'Cloud', icon: Cloud, note: 'Permission sets via SCIM' },
]
const critTone = { high: 'bad', medium: 'warn', low: 'ok' }

export default function SystemMap() {
  const [data, , error] = useLoad({ systems: api.systems })
  usePreline([data])
  if (!data) return <><ErrorBox error={error} /><Loading /></>
  const systems = data.systems

  return (
    <div className="space-y-6">
      <PageHeader icon={Network} eyebrow="Application inventory · NIST CM-8" title="System map"
        desc="Workday is authoritative. Entra ID federates sign-in (SAML / OIDC) and provisions accounts downstream (SCIM). Each app has an owner, a criticality and a provisioning method. Manual provisioning is where deprovisioning gets missed, and reconciliation proves it." />
      <ErrorBox error={error} />
      <Card title="Identity flow" subtitle="How an identity moves from HR to every application" delay={60}>
        <div className="flex gap-3 overflow-x-auto pb-2">
          {TIERS.map((t, ti) => {
            const list = systems.filter((s) => s.category === t.cat)
            if (!list.length) return null
            return (
              <div key={t.cat} className="flex shrink-0 items-stretch gap-3 animate-fade-up" style={{ animationDelay: `${ti * 90}ms` }}>
                <div className="w-52">
                  <div className="mb-2 flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wider text-zinc-400"><t.icon className="size-3.5 text-violet-300" /> {t.label}</div>
                  <div className="mb-2 text-[11px] text-zinc-600">{t.note}</div>
                  <div className="space-y-2">
                    {list.map((s) => (
                      <div key={s.id} className={`group rounded-xl border bg-zinc-950/50 p-3 transition-all hover:-translate-y-0.5 hover:border-violet-500/40 ${s.provisioning === 'Manual' ? 'border-amber-500/40' : 'border-white/[0.08]'}`}>
                        <div className="flex items-start justify-between gap-2">
                          <div className="text-sm font-semibold text-zinc-100">{s.name}</div>
                          <span className={`mt-1 size-2 shrink-0 rounded-full ${s.criticality === 'high' ? 'bg-rose-400' : s.criticality === 'medium' ? 'bg-amber-400' : 'bg-emerald-400'}`} />
                        </div>
                        <div className="mt-1 text-[11px] text-zinc-500">{s.authProtocol} · {s.provisioning}</div>
                        <div className="mt-2 flex items-center justify-between text-[11px]">
                          <span className="text-zinc-400">{s.users} users</span>
                          {s.provisioning === 'Manual' && <Tooltip tip="Leavers depend on someone working a ticket"><span className="inline-flex items-center gap-1 text-amber-300"><AlertTriangle className="size-3" /> manual</span></Tooltip>}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
                {ti < TIERS.length - 1 && <div className="flex items-center"><ChevronRight className="size-5 text-zinc-600" /></div>}
              </div>
            )
          })}
        </div>
      </Card>

      <Card title="Inventory" pad={false} delay={120}>
        <div className="overflow-x-auto">
          <table className="min-w-full">
            <thead><tr><th className="th ps-5">System</th><th className="th">Type</th><th className="th">Auth</th><th className="th">Provisioning</th><th className="th">Owner</th><th className="th">Criticality</th><th className="th">Users</th><th className="th">Entitlements</th><th className="th pe-5">Privileged grants</th></tr></thead>
            <tbody>
              {systems.map((s) => (
                <tr key={s.id} className="row">
                  <td className="td ps-5 font-medium text-zinc-100">{s.name}</td>
                  <td className="td text-zinc-400">{s.category}</td>
                  <td className="td text-zinc-300">{s.authProtocol}</td>
                  <td className="td">{s.provisioning === 'Manual' ? <Badge tone="warn">Manual</Badge> : <span className="text-zinc-300">{s.provisioning}</span>}</td>
                  <td className="td text-zinc-400">{s.owner}</td>
                  <td className="td"><Badge tone={critTone[s.criticality]}>{s.criticality}</Badge></td>
                  <td className="td tabular-nums text-zinc-300">{s.users}</td>
                  <td className="td tabular-nums text-zinc-300">{s.entitlements}</td>
                  <td className="td pe-5">{s.privilegedGrants > 0 ? <Badge tone="bad">{s.privilegedGrants}</Badge> : <span className="text-zinc-500">0</span>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  )
}
