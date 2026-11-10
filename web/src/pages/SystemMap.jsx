import { Network, Database, Fingerprint, FolderTree, AppWindow, Cloud } from 'lucide-react'
import { api } from '../api.js'
import { useLoad } from '../hooks.js'
import { PageHead, Badge, ErrorBox, Loading } from '../ui.jsx'

const TIERS = [
  { cat: 'hris', label: 'HR source of truth', icon: Database },
  { cat: 'idp', label: 'Identity provider', icon: Fingerprint },
  { cat: 'directory', label: 'Directory', icon: FolderTree },
  { cat: 'app', label: 'Applications', icon: AppWindow },
  { cat: 'cloud', label: 'Cloud', icon: Cloud },
]

const critKind = { high: 'bad', medium: 'warn', low: 'ok' }

export default function SystemMap() {
  const [data, , error] = useLoad({ systems: api.systems })
  if (!data) return <><ErrorBox error={error} /><Loading /></>
  const systems = data.systems

  return (
    <div>
      <PageHead icon={Network} title="System map" job="Application inventory & integrations" />
      <ErrorBox error={error} />

      <section className="panel">
        <h3>Identity flow</h3>
        <div className="flow">
          {TIERS.map((t, i) => {
            const list = systems.filter((s) => s.category === t.cat)
            if (!list.length) return null
            const Icon = t.icon
            return (
              <div className="flow-col" key={t.cat}>
                <div className="flow-head"><Icon size={16} /> {t.label}</div>
                {list.map((s) => (
                  <div className={`node crit-${s.criticality}`} key={s.id}>
                    <strong>{s.name}</strong>
                    <div className="muted small">{s.authProtocol} · {s.provisioning}</div>
                    <div className="small">{s.users} users</div>
                  </div>
                ))}
                {i < TIERS.length - 1 && <div className="flow-arrow" aria-hidden>→</div>}
              </div>
            )
          })}
        </div>
        <p className="muted small">
          Workday is the source of truth; Entra ID federates sign-in (SAML/OIDC) and pushes accounts (SCIM) downstream.
          Manual provisioning is where deprovisioning gets missed.
        </p>
      </section>

      <section className="panel">
        <h3>Inventory</h3>
        <div className="table-wrap">
          <table>
            <thead><tr><th>System</th><th>Type</th><th>Auth</th><th>Provisioning</th><th>Owner</th><th>Criticality</th><th>Users</th><th>Entitlements</th><th>Privileged grants</th></tr></thead>
            <tbody>
              {systems.map((s) => (
                <tr key={s.id}>
                  <td><strong>{s.name}</strong></td>
                  <td>{s.category}</td>
                  <td>{s.authProtocol}</td>
                  <td>{s.provisioning === 'Manual' ? <Badge kind="warn">Manual</Badge> : s.provisioning}</td>
                  <td>{s.owner}</td>
                  <td><Badge kind={critKind[s.criticality]}>{s.criticality}</Badge></td>
                  <td>{s.users}</td><td>{s.entitlements}</td>
                  <td>{s.privilegedGrants > 0 ? <Badge kind="bad">{s.privilegedGrants}</Badge> : 0}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  )
}
