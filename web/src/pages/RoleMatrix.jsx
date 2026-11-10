import { Grid3x3, Star } from 'lucide-react'
import { api } from '../api.js'
import { useLoad, useToast } from '../hooks.js'
import { PageHead, Toast, ErrorBox, Loading } from '../ui.jsx'

export default function RoleMatrix() {
  const [data, reload, error] = useLoad({ catalog: api.catalog, people: api.identities })
  const [toast, show] = useToast()

  if (!data) return <><ErrorBox error={error} /><Loading /></>
  const { roles, entitlements, systems, sodRules } = data.catalog
  const members = (roleId) => data.people.filter((p) => p.roleId === roleId && p.status === 'active').length
  const sysName = (id) => systems.find((s) => s.id === id)?.name || id

  // Would adding ent to role create an SoD conflict inside the role?
  const wouldConflict = (role, entId) =>
    sodRules.find((r) => (r.a === entId && role.entitlements.includes(r.b)) || (r.b === entId && role.entitlements.includes(r.a)))

  async function toggle(role, ent) {
    const granted = !role.entitlements.includes(ent.id)
    if (granted && ent.privileged &&
      !confirm(`${ent.name} is privileged. Making it birthright gives it to all ${members(role.id)} members of ${role.name}. Continue?`)) return
    try {
      const res = await api.setRoleEnt(role.id, ent.id, granted)
      await reload()
      show(`${ent.name} ${granted ? 'added to' : 'removed from'} ${role.name} · ${res.affected} identities re-synced`)
    } catch (e) { show(e.message, 'err') }
  }

  return (
    <div>
      <PageHead icon={Grid3x3} title="Role matrix" job="RBAC design · least privilege" />
      <ErrorBox error={error} />
      <p className="muted">
        Click a cell to add or remove an entitlement from a role. Members are re-synced immediately.
        Cells marked <span className="cell-demo blocked">⊘</span> are blocked by an SoD rule. <Star size={12} /> = privileged.
      </p>
      <section className="panel">
        <div className="table-wrap">
          <table className="matrix">
            <thead>
              <tr>
                <th className="sticky">Entitlement</th>
                {roles.map((r) => (
                  <th key={r.id} title={r.description}>
                    <div className="role-h">{r.name}</div>
                    <div className="muted small">{members(r.id)} {members(r.id) === 1 ? 'member' : 'members'}</div>
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {entitlements.map((e, i) => {
                const newSys = i === 0 || entitlements[i - 1].systemId !== e.systemId
                return (
                  <tr key={e.id} className={newSys ? 'sys-start' : ''}>
                    <td className="sticky">
                      {newSys && <div className="sys-label">{sysName(e.systemId)}</div>}
                      {e.name} {e.privileged && <Star size={12} className="priv" />}
                    </td>
                    {roles.map((r) => {
                      const on = r.entitlements.includes(e.id)
                      const block = !on && wouldConflict(r, e.id)
                      return (
                        <td key={r.id} className="cell-td">
                          <button
                            className={`cell ${on ? 'on' : ''} ${block ? 'blocked' : ''} ${on && e.privileged ? 'priv-on' : ''}`}
                            title={block ? `Blocked by ${block.id}: ${block.description}` : on ? 'Remove from role' : 'Add to role'}
                            onClick={() => (block ? show(`Blocked by ${block.id}: ${block.description}`, 'warn') : toggle(r, e))}
                          >
                            {on ? '✓' : block ? '⊘' : ''}
                          </button>
                        </td>
                      )
                    })}
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      </section>
      <Toast toast={toast} />
    </div>
  )
}
