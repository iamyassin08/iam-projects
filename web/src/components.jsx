import { useEffect, useState } from 'react'
import { Check, Copy, ShieldCheck, ShieldX, ShieldAlert, Smartphone, CheckCircle2, XCircle, MinusCircle } from 'lucide-react'
import { Badge, toast } from './ui.jsx'
import { totp, secondsLeft } from './totp.js'

// ---------- copyable code block ----------

export function CodeBlock({ children, lang, className = '', maxH = 'max-h-96' }) {
  const [done, setDone] = useState(false)
  const copy = async () => {
    try { await navigator.clipboard.writeText(children); setDone(true); setTimeout(() => setDone(false), 1400) } catch { toast('Copy failed', 'err') }
  }
  return (
    <div className={`group relative rounded-xl border border-white/[0.07] bg-zinc-950/80 ${className}`}>
      {lang && <div className="border-b border-white/[0.06] px-3 py-1.5 font-mono text-[10px] uppercase tracking-wider text-zinc-500">{lang}</div>}
      <button type="button" onClick={copy} aria-label="Copy"
        className="absolute end-2 top-1.5 inline-flex items-center gap-1 rounded-md bg-white/5 px-2 py-1 text-[11px] text-zinc-400 opacity-0 transition group-hover:opacity-100 hover:text-white">
        {done ? <Check className="size-3" /> : <Copy className="size-3" />} {done ? 'Copied' : 'Copy'}
      </button>
      <pre className={`overflow-auto p-3 font-mono text-[12px] leading-relaxed text-zinc-300 ${maxH}`}>{children}</pre>
    </div>
  )
}

// ---------- JWT, colour-coded like jwt.io ----------

export function JWTView({ raw }) {
  if (!raw) return null
  const [h, p, s] = raw.split('.')
  return (
    <div className="break-all rounded-xl border border-white/[0.07] bg-zinc-950/80 p-3 font-mono text-[11px] leading-relaxed">
      <span className="text-rose-300">{h}</span><span className="text-zinc-500">.</span>
      <span className="text-violet-300">{p}</span><span className="text-zinc-500">.</span>
      <span className="text-sky-300">{s}</span>
    </div>
  )
}

const claimHelp = {
  iss: 'Issuer: who minted the token. Must match the provider exactly.',
  sub: 'Subject: the stable user identifier.',
  aud: 'Audience: the client this token is for. Rejects tokens minted for other apps.',
  exp: 'Expiry (Unix time). Short-lived by design.',
  iat: 'Issued at.',
  auth_time: 'When the user actually authenticated.',
  nonce: 'Echo of the random value the client sent. Stops token replay.',
  amr: 'Authentication methods: pwd = password, otp = one-time code, mfa = multi-factor.',
  acr: 'Assurance level: 1 = single factor, 2 = MFA.',
  groups: 'Group memberships, used for authorization (RBAC) in the app.',
  scope: 'Permissions granted to the access token.',
  sid: 'Session id, used for logout.',
  jti: 'Unique token id.',
  client_id: 'The OAuth client that requested the token.',
  realm_access: 'Keycloak realm roles.',
}

export function ClaimsTable({ claims }) {
  if (!claims) return null
  const fmt = (k, v) => {
    if (['exp', 'iat', 'auth_time'].includes(k) && typeof v === 'number') return `${v}  (${new Date(v * 1000).toLocaleString()})`
    return typeof v === 'object' ? JSON.stringify(v) : String(v)
  }
  return (
    <div className="overflow-x-auto rounded-xl border border-white/[0.07]">
      <table className="min-w-full text-sm">
        <tbody>
          {Object.entries(claims).map(([k, v]) => (
            <tr key={k} className="row">
              <td className="td w-28 font-mono text-xs text-violet-300">{k}</td>
              <td className="td break-all font-mono text-xs text-zinc-200">{fmt(k, v)}</td>
              <td className="td hidden text-xs text-zinc-500 md:table-cell">{claimHelp[k] || ''}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

// ---------- Conditional Access evaluation ----------

const decisionMeta = {
  allow: { tone: 'ok', icon: ShieldCheck, label: 'Access granted' },
  mfa: { tone: 'warn', icon: ShieldAlert, label: 'MFA required' },
  block: { tone: 'bad', icon: ShieldX, label: 'Blocked' },
}

export function CAEvalView({ ev, compact }) {
  if (!ev) return null
  const m = decisionMeta[ev.decision] || decisionMeta.allow
  const Icon = m.icon
  return (
    <div className="space-y-3">
      <div className={`flex flex-wrap items-center gap-3 rounded-xl border p-3 ${m.tone === 'bad' ? 'border-rose-500/30 bg-rose-500/10' : m.tone === 'warn' ? 'border-amber-500/30 bg-amber-500/10' : 'border-emerald-500/30 bg-emerald-500/10'}`}>
        <Icon className={`size-5 ${m.tone === 'bad' ? 'text-rose-300' : m.tone === 'warn' ? 'text-amber-300' : 'text-emerald-300'}`} />
        <span className="font-semibold text-white">{m.label}</span>
        <Badge tone={ev.risk === 'high' ? 'bad' : ev.risk === 'medium' ? 'warn' : 'ok'}>sign-in risk: {ev.risk}</Badge>
        {ev.reportOnly?.length > 0 && <Badge tone="info">report-only: {ev.reportOnly.join(' · ')}</Badge>}
      </div>
      {!compact && (
        <ul className="space-y-1.5">
          {ev.results.map((r) => {
            const RIcon = !r.applies ? MinusCircle : r.grant === 'block' ? XCircle : CheckCircle2
            return (
              <li key={r.id} className={`rounded-lg border px-3 py-2 text-xs ${r.applies ? 'border-white/10 bg-white/[0.03]' : 'border-white/[0.04] opacity-60'}`}>
                <div className="flex flex-wrap items-center gap-2">
                  <RIcon className={`size-3.5 ${!r.applies ? 'text-zinc-500' : r.grant === 'block' ? 'text-rose-400' : 'text-amber-300'}`} />
                  <span className="font-mono text-zinc-400">{r.id}</span>
                  <span className="font-medium text-zinc-200">{r.name}</span>
                  <Badge tone={r.state === 'on' ? 'ok' : r.state === 'report-only' ? 'info' : 'neutral'}>{r.state}</Badge>
                  {r.applies && <Badge tone={r.grant === 'block' ? 'bad' : 'warn'}>{r.state === 'report-only' ? 'would ' : ''}{r.grant === 'block' ? 'block' : 'require MFA'}</Badge>}
                </div>
                <div className="mt-1 flex flex-wrap gap-x-3 gap-y-0.5 ps-5 text-zinc-500">{r.why.map((w, i) => <span key={i}>{w}</span>)}</div>
              </li>
            )
          })}
        </ul>
      )}
    </div>
  )
}

// ---------- virtual authenticator (demo) ----------

export function useTOTP(secret) {
  const [code, setCode] = useState('------')
  const [left, setLeft] = useState(secondsLeft())
  useEffect(() => {
    if (!secret) return
    let alive = true
    const tick = async () => {
      setLeft(secondsLeft())
      const c = await totp(secret).catch(() => '------')
      if (alive) setCode(c)
    }
    tick()
    const t = setInterval(tick, 1000)
    return () => { alive = false; clearInterval(t) }
  }, [secret])
  return [code, left]
}

export function AuthenticatorTile({ label, secret, onUse }) {
  const [code, left] = useTOTP(secret)
  const pct = (left / 30) * 100
  return (
    <div className="flex items-center gap-3 rounded-xl border border-white/[0.07] bg-zinc-950/60 px-3 py-2.5">
      <Smartphone className="size-4 shrink-0 text-violet-300" />
      <div className="min-w-0 flex-1">
        <div className="truncate text-[11px] text-zinc-500">{label}</div>
        <div className="font-mono text-xl font-bold tracking-[0.25em] text-white tabular-nums">{code.slice(0, 3)} {code.slice(3)}</div>
      </div>
      <svg viewBox="0 0 36 36" className="size-8 -rotate-90" aria-label={`${left}s left`}>
        <circle cx="18" cy="18" r="15" fill="none" stroke="rgba(255,255,255,.08)" strokeWidth="4" />
        <circle cx="18" cy="18" r="15" fill="none" stroke={left <= 5 ? '#fb7185' : '#a78bfa'} strokeWidth="4" strokeDasharray={94.2} strokeDashoffset={94.2 * (1 - pct / 100)} strokeLinecap="round" style={{ transition: 'stroke-dashoffset 1s linear' }} />
      </svg>
      {onUse && <button type="button" onClick={() => onUse(code)} className="rounded-lg bg-white/5 px-2.5 py-1.5 text-xs font-semibold text-zinc-200 hover:bg-white/10">Use</button>}
    </div>
  )
}

// ---------- step-by-step sequence diagram ----------
// lanes: ['Browser', 'App', 'IdP']; steps: [{ from: 0, to: 2, label, note }]

export function Sequence({ lanes, steps, active = -1, onStep }) {
  const w = 680, laneX = (i) => 70 + i * ((w - 140) / (lanes.length - 1)), rowH = 44, top = 56
  const h = top + steps.length * rowH + 20
  return (
    <div className="overflow-x-auto">
      <svg viewBox={`0 0 ${w} ${h}`} className="min-w-[560px] w-full" role="img" aria-label="Sequence diagram">
        <defs>
          <marker id="arr" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0 0 10 5 0 10z" fill="#a78bfa" /></marker>
          <marker id="arr-dim" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0 0 10 5 0 10z" fill="#52525b" /></marker>
        </defs>
        {lanes.map((l, i) => (
          <g key={l}>
            <rect x={laneX(i) - 58} y={8} width={116} height={30} rx={8} fill="rgba(139,92,246,.12)" stroke="rgba(139,92,246,.4)" />
            <text x={laneX(i)} y={28} textAnchor="middle" className="fill-zinc-100 text-[12px] font-semibold">{l}</text>
            <line x1={laneX(i)} x2={laneX(i)} y1={40} y2={h - 8} stroke="rgba(255,255,255,.1)" strokeDasharray="4 4" />
          </g>
        ))}
        {steps.map((s, i) => {
          const y = top + i * rowH + 18, x1 = laneX(s.from), x2 = laneX(s.to), on = active < 0 || i <= active, cur = i === active
          const self = s.from === s.to
          return (
            <g key={i} className="cursor-pointer" onClick={() => onStep?.(i)} opacity={on ? 1 : 0.35}>
              {self ? (
                <path d={`M${x1} ${y - 6} h30 v14 h-28`} fill="none" stroke={cur ? '#c4b5fd' : on ? '#a78bfa' : '#52525b'} strokeWidth={cur ? 2.2 : 1.4} markerEnd={on ? 'url(#arr)' : 'url(#arr-dim)'} />
              ) : (
                <line x1={x1} x2={x2 + (x2 > x1 ? -4 : 4)} y1={y} y2={y} stroke={cur ? '#c4b5fd' : on ? '#a78bfa' : '#52525b'} strokeWidth={cur ? 2.2 : 1.4} markerEnd={on ? 'url(#arr)' : 'url(#arr-dim)'} />
              )}
              <circle cx={Math.min(x1, x2) - 16} cy={y} r={9} fill={cur ? '#8b5cf6' : 'rgba(139,92,246,.2)'} />
              <text x={Math.min(x1, x2) - 16} y={y + 3.5} textAnchor="middle" className="fill-white text-[10px] font-bold">{i + 1}</text>
              <text x={self ? x1 + 38 : (x1 + x2) / 2} y={y - 7} textAnchor={self ? 'start' : 'middle'} className={`text-[11px] ${cur ? 'fill-white font-semibold' : 'fill-zinc-300'}`}>{s.label}</text>
            </g>
          )
        })}
      </svg>
    </div>
  )
}

// ---------- simple left-to-right flow (boxes and arrows) ----------

export function Flow({ nodes, tone = 'violet' }) {
  const ring = { violet: 'border-violet-500/30 bg-violet-500/[0.07]', sky: 'border-sky-500/30 bg-sky-500/[0.07]', emerald: 'border-emerald-500/30 bg-emerald-500/[0.07]', amber: 'border-amber-500/30 bg-amber-500/[0.07]', rose: 'border-rose-500/30 bg-rose-500/[0.07]' }
  return (
    <div className="flex flex-col items-stretch gap-2 md:flex-row md:items-center">
      {nodes.map((n, i) => (
        <div key={i} className="contents">
          <div className={`flex-1 rounded-xl border px-3 py-2.5 text-center animate-fade-up ${ring[n.tone || tone]}`} style={{ animationDelay: `${i * 70}ms` }}>
            <div className="text-[13px] font-semibold text-zinc-100">{n.title}</div>
            {n.sub && <div className="mt-0.5 text-[11px] leading-snug text-zinc-400">{n.sub}</div>}
          </div>
          {i < nodes.length - 1 && <div className="self-center text-violet-400 md:rotate-0 rotate-90">→</div>}
        </div>
      ))}
    </div>
  )
}
