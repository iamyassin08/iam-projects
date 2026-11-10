// Thin fetch wrapper for the Go API. Every call sends X-Actor so the
// audit log records who did it.
const ACTOR = 'yassin.iam'

async function call(method, path, body) {
  const res = await fetch(`/api${path}`, {
    method,
    headers: { 'Content-Type': 'application/json', 'X-Actor': ACTOR },
    body: body ? JSON.stringify(body) : undefined,
  })
  const data = await res.json().catch(() => ({}))
  if (!res.ok) throw new Error(data.error || `${res.status} ${res.statusText}`)
  return data
}

export const api = {
  summary: () => call('GET', '/summary'),
  catalog: () => call('GET', '/catalog'),
  identities: () => call('GET', '/identities'),
  access: (id) => call('GET', `/identities/${id}/access`),
  jmlEvents: () => call('GET', '/jml/events'),
  joiner: (b) => call('POST', '/jml/joiner', b),
  mover: (b) => call('POST', '/jml/mover', b),
  leaver: (b) => call('POST', '/jml/leaver', b),
  requests: () => call('GET', '/requests'),
  newRequest: (b) => call('POST', '/requests', b),
  approve: (id, reason) => call('POST', `/requests/${id}/approve`, { reason }),
  deny: (id, reason) => call('POST', `/requests/${id}/deny`, { reason }),
  setRoleEnt: (roleId, entitlementId, granted) =>
    call('PUT', `/roles/${roleId}/entitlements`, { entitlementId, granted }),
  systems: () => call('GET', '/systems'),
  audit: () => call('GET', '/audit'),
  checks: () => call('GET', '/lab/checks'),
  reset: () => call('POST', '/reset'),
}

export const fmtDate = (s) => (s ? new Date(s).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' }) : '—')
