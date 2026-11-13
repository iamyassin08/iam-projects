import { useState } from 'react'
import { Plug, KeyRound, Copy, Send, Trash2, Terminal, ShieldCheck, Loader2 } from 'lucide-react'
import { api, ago } from '../api.js'
import { useLoad, PageHeader, Card, Badge, Button, ErrorBox, Loading, ask, toast, Modal, openModal, usePreline, Empty } from '../ui.jsx'

const P = (o) => JSON.stringify(o, null, 2)
const PRESETS = [
  { group: 'Discovery', label: 'ServiceProviderConfig', method: 'GET', path: '/ServiceProviderConfig' },
  { group: 'Discovery', label: 'ResourceTypes', method: 'GET', path: '/ResourceTypes' },
  { group: 'Users', label: 'List users (paged)', method: 'GET', path: '/Users?startIndex=1&count=3' },
  { group: 'Users', label: 'Filter by userName', method: 'GET', path: '/Users?filter=userName eq "omar.farouk@demo.local"' },
  {
    group: 'Lifecycle', label: 'Create user (joiner)', method: 'POST', path: '/Users', body: P({
      schemas: ['urn:ietf:params:scim:schemas:core:2.0:User', 'urn:ietf:params:scim:schemas:extension:enterprise:2.0:User'],
      userName: 'nadia.karim@demo.local', externalId: 'WD-20991', name: { givenName: 'Nadia', familyName: 'Karim' },
      title: 'AP Specialist', active: true, emails: [{ value: 'nadia.karim@demo.local', type: 'work', primary: true }],
      groups: [{ value: 'r-ap' }],
      'urn:ietf:params:scim:schemas:extension:enterprise:2.0:User': { department: 'Finance', manager: { displayName: 'Grace Kim' } },
    }),
  },
  { group: 'Lifecycle', label: 'Update title (PATCH)', method: 'PATCH', path: '/Users/{id}', body: P({ schemas: ['urn:ietf:params:scim:api:messages:2.0:PatchOp'], Operations: [{ op: 'replace', path: 'title', value: 'Senior AP Specialist' }] }) },
  { group: 'Lifecycle', label: 'Move via group (mover)', method: 'PATCH', path: '/Groups/r-sales', body: P({ schemas: ['urn:ietf:params:scim:api:messages:2.0:PatchOp'], Operations: [{ op: 'add', path: 'members', value: [{ value: '{id}' }] }] }) },
  { group: 'Lifecycle', label: 'Deactivate, Entra style (leaver)', method: 'PATCH', path: '/Users/{id}', body: P({ schemas: ['urn:ietf:params:scim:api:messages:2.0:PatchOp'], Operations: [{ op: 'Replace', path: 'active', value: 'False' }] }) },
  { group: 'Lifecycle', label: 'Reactivate (rehire)', method: 'PATCH', path: '/Users/{id}', body: P({ schemas: ['urn:ietf:params:scim:api:messages:2.0:PatchOp'], Operations: [{ op: 'replace', value: { active: true } }] }) },
  { group: 'Lifecycle', label: 'Delete user', method: 'DELETE', path: '/Users/{id}' },
  { group: 'Groups', label: 'List groups (roles)', method: 'GET', path: '/Groups' },
  { group: 'Errors', label: 'Unsupported filter', method: 'GET', path: '/Users?filter=title pr or active eq true' },
]
const methodTone = { GET: 'info', POST: 'ok', PATCH: 'warn', PUT: 'warn', DELETE: 'bad' }

export default function SCIM() {
  const [data, reload, error] = useLoad({ tokens: api.tokens })
  const [token, setToken] = useState('')
  const [fresh, setFresh] = useState(null)
  const [lastId, setLastId] = useState('ID-1')
  const [req, setReq] = useState({ method: 'GET', path: '/ServiceProviderConfig', body: '' })
  const [res, setRes] = useState(null)
  const [busy, setBusy] = useState(false)
  usePreline([data, res])

  const base = `${window.location.origin}/scim/v2`
  const resolvedPath = req.path.replaceAll('{id}', lastId)
  const resolvedBody = req.body.replaceAll('{id}', lastId)

  async function create() {
    const name = await ask({ title: 'Issue a SCIM bearer token', message: 'Paste it into your IdP\'s provisioning settings (Entra ID: Secret Token; Okta: API token). Only a SHA-256 hash is stored, so it is shown once.', input: 'text', label: 'Token name', defaultValue: 'Entra ID provisioning (lab)', required: true, confirm: 'Generate' })
    if (!name) return
    try {
      const t = await api.newToken(name)
      setToken(t.token); setFresh(t)
      await reload()
      setTimeout(() => openModal('token-modal'), 0)
    } catch (e) { toast(e.message, 'err') }
  }
  async function revoke(t) {
    const ok = await ask({ title: `Revoke “${t.name}”?`, message: 'Any IdP using it will start receiving 401 Unauthorized.', input: false, confirm: 'Revoke', tone: 'danger' })
    if (!ok) return
    try { await api.revokeToken(t.id); await reload(); toast('Token revoked') } catch (e) { toast(e.message, 'err') }
  }
  async function send() {
    setBusy(true)
    const started = performance.now()
    try {
      const r = await fetch(`/scim/v2${resolvedPath}`, {
        method: req.method,
        headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/scim+json', Accept: 'application/scim+json' },
        body: ['GET', 'DELETE'].includes(req.method) ? undefined : resolvedBody,
      })
      const text = await r.text()
      let json = null
      try { json = JSON.parse(text) } catch { /* empty body */ }
      if (r.ok && req.method === 'POST' && json?.id) setLastId(json.id)
      setRes({ status: r.status, statusText: r.statusText, ms: Math.round(performance.now() - started), headers: [...r.headers.entries()], body: json ? P(json) : text || '(no content)' })
      reload()
    } catch (e) { toast(e.message, 'err') } finally { setBusy(false) }
  }
  const curl = [`curl -X ${req.method} '${base}${resolvedPath}'`, `  -H 'Authorization: Bearer ${token || '<token>'}'`, `  -H 'Content-Type: application/scim+json'`, ...(['GET', 'DELETE'].includes(req.method) || !req.body ? [] : [`  -d '${resolvedBody.replace(/\n\s*/g, ' ')}'`])].join(' \\\n')
  const copy = (t) => navigator.clipboard?.writeText(t).then(() => toast('Copied to clipboard', 'info'))

  if (!data) return <><ErrorBox error={error} /><Loading /></>
  const groups = [...new Set(PRESETS.map((p) => p.group))]

  return (
    <div className="space-y-6">
      <PageHeader icon={Plug} eyebrow="Inbound provisioning · RFC 7643 / 7644" title="SCIM 2.0 provisioning"
        desc="A real SCIM service provider. Users map to identities and Groups map to RBAC roles: POST is a joiner, a group membership change is a mover, active=false or DELETE is a leaver. It accepts Entra ID's quirks (capitalised ops, string booleans), supports filter and paging, and returns RFC-compliant error bodies. Point an IdP at the base URL with a token from here." />
      <ErrorBox error={error} />

      <div className="grid gap-6 lg:grid-cols-3">
        <Card title="Endpoint" delay={40}>
          <div className="label">Tenant URL</div>
          <div className="flex items-center gap-2">
            <code className="code block flex-1 truncate py-2">{base}</code>
            <Button size="sm" variant="ghost" onClick={() => copy(base)} aria-label="Copy URL"><Copy className="size-3.5" /></Button>
          </div>
          <div className="label mt-4">Bearer token for this console</div>
          <input className="input font-mono text-xs" value={token} onChange={(e) => setToken(e.target.value)} placeholder="scim_… (generate one →)" />
          <Button className="mt-3 w-full" onClick={create}><KeyRound className="size-4" /> Generate token</Button>
          <p className="mt-3 text-[11px] leading-relaxed text-zinc-500">Tokens are 192-bit random values. The server stores only a SHA-256 hash and compares in constant time. Control C14 flags tokens older than 90 days.</p>
        </Card>

        <Card className="lg:col-span-2" title="Provisioning credentials" subtitle="Each token is attributed in the audit log as scim:&lt;name&gt;" delay={80} pad={false}>
          {data.tokens.length === 0 ? <Empty icon={KeyRound}>No tokens yet.</Empty> : (
            <div className="overflow-x-auto">
              <table className="min-w-full">
                <thead><tr><th className="th ps-5">Name</th><th className="th">Prefix</th><th className="th">Age</th><th className="th">Last used</th><th className="th">Requests</th><th className="th pe-5" /></tr></thead>
                <tbody>
                  {data.tokens.map((t) => (
                    <tr key={t.id} className={`row ${t.revoked ? 'opacity-50' : ''}`}>
                      <td className="td ps-5 text-zinc-100">{t.name}<div className="text-xs text-zinc-500">by {t.createdBy}</div></td>
                      <td className="td"><span className="code">{t.prefix}…</span></td>
                      <td className="td">{t.ageDays > 90 ? <Badge tone="bad">{t.ageDays}d</Badge> : <span className="text-zinc-400">{t.ageDays}d</span>}</td>
                      <td className="td text-zinc-400">{ago(t.lastUsed)}</td>
                      <td className="td tabular-nums text-zinc-300">{t.requests}</td>
                      <td className="td pe-5 text-end">{t.revoked ? <Badge tone="neutral">revoked</Badge> : <Button size="sm" variant="subtle" onClick={() => revoke(t)}><Trash2 className="size-3.5" /> Revoke</Button>}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
      </div>

      <div className="grid gap-6 xl:grid-cols-2">
        <Card title="Request" subtitle={<>Placeholders: <span className="code">{'{id}'}</span> = {lastId} (the last user you created)</>} delay={120}>
          <div className="mb-4 space-y-2">
            {groups.map((g) => (
              <div key={g} className="flex flex-wrap items-center gap-1.5">
                <span className="w-20 text-[10px] font-semibold uppercase tracking-wider text-zinc-500">{g}</span>
                {PRESETS.filter((p) => p.group === g).map((p) => (
                  <button key={p.label} type="button" onClick={() => setReq({ method: p.method, path: p.path, body: p.body || '' })}
                    className={`rounded-lg border px-2.5 py-1 text-xs transition-all hover:-translate-y-px ${req.path === p.path && req.method === p.method && (req.body || '') === (p.body || '') ? 'border-violet-500/60 bg-violet-500/15 text-violet-200' : 'border-white/10 text-zinc-300 hover:border-white/25'}`}>
                    {p.label}
                  </button>
                ))}
              </div>
            ))}
          </div>
          <div className="flex gap-2">
            <select className="input w-28 font-mono text-xs" value={req.method} onChange={(e) => setReq({ ...req, method: e.target.value })}>{['GET', 'POST', 'PATCH', 'PUT', 'DELETE'].map((m) => <option key={m}>{m}</option>)}</select>
            <input className="input flex-1 font-mono text-xs" value={req.path} onChange={(e) => setReq({ ...req, path: e.target.value })} />
          </div>
          {!['GET', 'DELETE'].includes(req.method) && (
            <textarea rows={11} spellCheck={false} className="input mt-2 font-mono text-[12px] leading-relaxed" value={req.body} onChange={(e) => setReq({ ...req, body: e.target.value })} />
          )}
          <div className="mt-3 flex items-center justify-between gap-2">
            {!token ? <span className="text-xs text-amber-300">Generate or paste a token first.</span> : <span className="text-xs text-zinc-500">Sends <span className="code">Authorization: Bearer {token.slice(0, 10)}…</span></span>}
            <Button onClick={send} disabled={busy}>{busy ? <Loader2 className="size-4 animate-spin" /> : <Send className="size-4" />} Send</Button>
          </div>
        </Card>

        <Card title="Response" delay={160}
          actions={res && <Badge tone={res.status < 300 ? 'ok' : res.status < 500 ? 'warn' : 'bad'} dot>{res.status} {res.statusText} · {res.ms} ms</Badge>}>
          <nav className="mb-3 flex gap-1 rounded-lg border border-white/10 bg-zinc-950/60 p-0.5" aria-label="Response tabs" role="tablist" aria-orientation="horizontal">
            {[['body', 'Body'], ['headers', 'Headers'], ['curl', 'cURL']].map(([id, label], i) => (
              <button key={id} type="button" id={`scim-tab-${id}`} role="tab" aria-selected={i === 0} data-hs-tab={`#scim-panel-${id}`} aria-controls={`scim-panel-${id}`}
                className={`hs-tab-active:bg-white/10 hs-tab-active:text-white flex-1 rounded-md px-3 py-1.5 text-xs font-semibold text-zinc-400 transition hover:text-zinc-200 ${i === 0 ? 'active' : ''}`}>
                {label}
              </button>
            ))}
          </nav>
          <div id="scim-panel-body" role="tabpanel" aria-labelledby="scim-tab-body">
            {res ? <pre key={res.ms + res.status} className="max-h-[440px] overflow-auto rounded-xl bg-zinc-950 p-4 font-mono text-[12px] leading-relaxed text-emerald-200/90 animate-fade-in">{res.body}</pre>
              : <Empty icon={Terminal}>Pick a preset and send it.</Empty>}
          </div>
          <div id="scim-panel-headers" role="tabpanel" aria-labelledby="scim-tab-headers" className="hidden">
            <pre className="max-h-[440px] overflow-auto rounded-xl bg-zinc-950 p-4 font-mono text-[12px] leading-relaxed text-zinc-300">{res ? res.headers.map(([k, v]) => `${k}: ${v}`).join('\n') : '—'}</pre>
          </div>
          <div id="scim-panel-curl" role="tabpanel" aria-labelledby="scim-tab-curl" className="hidden">
            <div className="relative">
              <pre className="max-h-[440px] overflow-auto rounded-xl bg-zinc-950 p-4 pt-12 font-mono text-[12px] leading-relaxed text-sky-200/90">{curl}</pre>
              <Button size="sm" variant="ghost" className="absolute end-2 top-2" onClick={() => copy(curl)}><Copy className="size-3.5" /> Copy</Button>
            </div>
          </div>
        </Card>
      </div>

      <Modal id="token-modal" size="md" title="Token created" footer={<Button data-hs-overlay="#token-modal">Done</Button>}>
        <div className="flex items-start gap-3 rounded-xl border border-amber-500/30 bg-amber-500/10 p-3 text-xs text-amber-200"><ShieldCheck className="mt-0.5 size-4 shrink-0" /> Copy it now. It will not be shown again; only its hash is stored. It's loaded into this console already.</div>
        <div className="mt-4 flex items-center gap-2">
          <code className="code block flex-1 break-all py-2 text-[12px]">{fresh?.token}</code>
          <Button size="sm" variant="ghost" onClick={() => copy(fresh?.token || '')}><Copy className="size-3.5" /></Button>
        </div>
      </Modal>
    </div>
  )
}
