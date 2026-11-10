import { Grid3x3, Star, Ban, Check } from 'lucide-react'
import { api } from '../api.js'
import { useLoad, PageHeader, Card, ErrorBox, Loading, ask, toast, usePreline, Badge } from '../ui.jsx'

export default function RoleMatrix() {
  const [data, reload, error] = useLoad({ catalog: api.catalog, people: api.identities })
  usePreline([data])
  if (!data) return <><ErrorBox error={error} /><Loading /></>
  const { roles, entitlements, systems, sodRules } = data.catalog
  const members = (roleId) => data.people.filter((p) => p.roleId === roleId && p.status === 'active').length
  const sysName = (id) => systems.find((s) => s.id === id)?.name || id
  const conflict = (role, entId) =>
    sodRules.find((r) => (r.a === entId && role.entitlements.includes(r.b)) || (r.b === entId && role.entitlements.includes(r.a)))

  async function toggle(role, ent) {
    const granted = !role.entitlements.includes(ent.id)
    if (granted && ent.privileged) {
      const ok = await ask({ title: 'Make privileged access birthright?', message: <><span className="font-semibold text-zinc-100">{ent.name}</span> would go to all {members(role.id)} members of {role.name} with no request or expiry. Control C6 will flag this. Prefer JIT eligibility instead.</>, input: false, confirm: 'Add anyway', tone: 'danger' })
      if (!ok) return
    }
    try {
      const res = await api.setRoleEnt(role.id, ent.id, granted)
      await reload()
      toast(`${ent.name} ${granted ? 'added to' : 'removed from'} ${role.name} · ${res.affected} identities re-synced`)
    } catch (e) { toast(e.message, 'err') }
  }

  return (
    <div className="space-y-6">
      <PageHeader icon={Grid3x3} eyebrow="RBAC design · least privilege · NIST AC-6" title="Role matrix"
        desc="Roles hold only what everyone in the job needs. Toggling a cell re-syncs every active member immediately. The API refuses any role that would contain both sides of an SoD rule, so toxic combinations can't be baked into birthright access." />
      <ErrorBox error={error} />
      <div className="flex flex-wrap gap-3 text-xs text-zinc-400 animate-fade-in">
        <span className="inline-flex items-center gap-1.5"><span className="inline-flex size-5 items-center justify-center rounded bg-violet-500/25 ring-1 ring-violet-500/50"><Check className="size-3 text-violet-200" /></span> in role</span>
        <span className="inline-flex items-center gap-1.5"><span className="inline-flex size-5 items-center justify-center rounded bg-rose-500/25 ring-1 ring-rose-500/50"><Check className="size-3 text-rose-200" /></span> privileged birthright (finding)</span>
        <span className="inline-flex items-center gap-1.5"><span className="inline-flex size-5 items-center justify-center rounded ring-1 ring-amber-500/40"><Ban className="size-3 text-amber-300" /></span> blocked by SoD</span>
        <span className="inline-flex items-center gap-1.5"><Star className="size-3.5 fill-amber-400 text-amber-400" /> privileged entitlement</span>
      </div>
      <Card pad={false} delay={80}>
        <div className="overflow-x-auto">
          <table className="min-w-full">
            <thead>
              <tr>
                <th className="th sticky start-0 z-10 bg-zinc-900 ps-5">Entitlement</th>
                {roles.map((r) => (
                  <th key={r.id} className="th text-center normal-case tracking-normal">
                    <div className="text-xs font-semibold text-zinc-200">{r.name}</div>
                    <div className="mt-0.5 text-[11px] font-normal text-zinc-500">{members(r.id)} {members(r.id) === 1 ? 'member' : 'members'}</div>
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {entitlements.map((e, i) => {
                const first = i === 0 || entitlements[i - 1].systemId !== e.systemId
                return (
                  <tr key={e.id} className={`transition-colors hover:bg-white/[0.02] ${first ? 'border-t-2 border-white/[0.08]' : 'border-t border-white/[0.04]'}`}>
                    <td className="td sticky start-0 z-10 min-w-56 bg-zinc-900 ps-5">
                      {first && <div className="mb-0.5 text-[10px] font-semibold uppercase tracking-wider text-violet-300">{sysName(e.systemId)}</div>}
                      <span className="text-zinc-200">{e.name}</span> {e.privileged && <Star className="inline size-3 fill-amber-400 text-amber-400" />}
                    </td>
                    {roles.map((r) => {
                      const on = r.entitlements.includes(e.id)
                      const block = !on && conflict(r, e.id)
                      return (
                        <td key={r.id} className="p-1.5 text-center">
                          <span className="hs-tooltip inline-block [--placement:top]">
                            <button type="button" onClick={() => (block ? toast(`Blocked by ${block.id}: ${block.description}`, 'warn') : toggle(r, e))}
                              className={`hs-tooltip-toggle inline-flex size-8 items-center justify-center rounded-lg ring-1 transition-all duration-200 hover:scale-110 active:scale-95
                                ${on ? (e.privileged ? 'bg-rose-500/25 ring-rose-500/50' : 'bg-violet-500/25 ring-violet-500/50') : block ? 'cursor-not-allowed ring-amber-500/30' : 'bg-zinc-950/60 ring-white/10 hover:ring-violet-500/50'}`}
                              aria-label={`${on ? 'Remove' : 'Add'} ${e.name} ${on ? 'from' : 'to'} ${r.name}`}>
                              {on ? <Check className={`size-4 ${e.privileged ? 'text-rose-200' : 'text-violet-200'}`} /> : block ? <Ban className="size-3.5 text-amber-300" /> : null}
                            </button>
                            <span role="tooltip" className="hs-tooltip-content invisible absolute z-[70] max-w-xs rounded-lg border border-white/10 bg-zinc-800 px-2.5 py-1.5 text-xs text-zinc-100 opacity-0 shadow-xl transition-opacity hs-tooltip-shown:visible hs-tooltip-shown:opacity-100">
                              {block ? `${block.id}: ${block.description}` : on ? `Remove from ${r.name}` : `Add to ${r.name}`}
                            </span>
                          </span>
                        </td>
                      )
                    })}
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      </Card>
      <div className="flex flex-wrap gap-2 text-xs text-zinc-500">{sodRules.map((r) => <Badge key={r.id} tone="warn">{r.id}: {r.description}</Badge>)}</div>
    </div>
  )
}
