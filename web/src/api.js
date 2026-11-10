// Thin fetch wrapper for the Go API. Every call sends X-Actor so the
// audit log records who did it.
export const ACTOR = 'yassin.iam'

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
  setRoleEnt: (roleId, entitlementId, granted) => call('PUT', `/roles/${roleId}/entitlements`, { entitlementId, granted }),
  revokeGrant: (b) => call('POST', '/grants/revoke', b),
  systems: () => call('GET', '/systems'),
  audit: () => call('GET', '/audit'),
  checks: () => call('GET', '/lab/checks'),
  reset: () => call('POST', '/reset'),
  // certifications
  campaigns: () => call('GET', '/certifications'),
  campaign: (id) => call('GET', `/certifications/${id}`),
  launchCampaign: (b) => call('POST', '/certifications', b),
  decideItem: (cid, iid, decision, comment) => call('POST', `/certifications/${cid}/items/${iid}`, { decision, comment }),
  closeCampaign: (cid) => call('POST', `/certifications/${cid}/close`),
  // JIT / PAM
  pam: () => call('GET', '/pam'),
  elevate: (b) => call('POST', '/pam/elevate', b),
  endSession: (id) => call('POST', `/pam/sessions/${id}/revoke`),
  reviewSession: (id, notes) => call('POST', `/pam/sessions/${id}/review`, { notes }),
  addEligibility: (b) => call('POST', '/pam/eligibility', b),
  removeEligibility: (identityId, entitlementId) =>
    call('DELETE', `/pam/eligibility?identityId=${encodeURIComponent(identityId)}&entitlementId=${encodeURIComponent(entitlementId)}`),
  // risk & reconciliation
  risk: () => call('GET', '/risk'),
  recon: () => call('GET', '/reconciliation'),
  accountAction: (id, b) => call('POST', `/reconciliation/accounts/${id}`, b),
  // SCIM token admin
  tokens: () => call('GET', '/scim/tokens'),
  newToken: (name) => call('POST', '/scim/tokens', { name }),
  revokeToken: (id) => call('DELETE', `/scim/tokens/${id}`),
}

export const fmtDate = (s) => (s ? new Date(s).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' }) : '—')
export const fmtDay = (s) => (s ? new Date(s).toLocaleDateString(undefined, { dateStyle: 'medium' }) : '—')

export function ago(s) {
  if (!s) return 'never'
  const d = (Date.now() - new Date(s).getTime()) / 1000
  if (d < 0) return 'in ' + until(s)
  if (d < 60) return 'just now'
  if (d < 3600) return `${Math.floor(d / 60)}m ago`
  if (d < 86400) return `${Math.floor(d / 3600)}h ago`
  return `${Math.floor(d / 86400)}d ago`
}

export function until(s) {
  const d = Math.max(0, (new Date(s).getTime() - Date.now()) / 1000)
  const m = Math.floor(d / 60), sec = Math.floor(d % 60)
  if (m >= 60) return `${Math.floor(m / 60)}h ${m % 60}m`
  return `${m}m ${String(sec).padStart(2, '0')}s`
}

export function downloadFile(name, text, type = 'text/plain') {
  const url = URL.createObjectURL(new Blob([text], { type }))
  Object.assign(document.createElement('a'), { href: url, download: name }).click()
  URL.revokeObjectURL(url)
}

export function toCSV(rows, head) {
  const esc = (v) => `"${String(v ?? '').replace(/"/g, '""')}"`
  return [head.join(','), ...rows.map((r) => head.map((h) => esc(r[h])).join(','))].join('\n')
}
