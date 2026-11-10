// Turn the catalog + directory into fast name lookups used across pages.
export function makeLookups(catalog, people = []) {
  const ent = Object.fromEntries((catalog?.entitlements || []).map((e) => [e.id, e]))
  const sys = Object.fromEntries((catalog?.systems || []).map((s) => [s.id, s]))
  const role = Object.fromEntries((catalog?.roles || []).map((r) => [r.id, r]))
  const ppl = Object.fromEntries(people.map((p) => [p.id, p]))
  return {
    ent, sys, role, ppl,
    entName: (id) => ent[id]?.name || id,
    sysOf: (entId) => sys[ent[entId]?.systemId]?.name || '',
    roleName: (id) => role[id]?.name || (id ? id : 'No role'),
    person: (id) => ppl[id]?.name || id,
  }
}
