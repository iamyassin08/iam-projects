import { useCallback, useEffect, useRef, useState } from 'react'
import { AlertTriangle, CheckCircle2, Info, X, XCircle } from 'lucide-react'

// ---------- Preline glue ----------

const PLUGINS = { overlay: 'HSOverlay', accordion: 'HSAccordion', tooltip: 'HSTooltip', tabs: 'HSTabs' }

// Initialise Preline plugins for any data-hs-* markup React has rendered since last time.
export function prelineInit(which = Object.keys(PLUGINS)) {
  which.forEach((k) => window[PLUGINS[k]]?.autoInit?.())
}

// Re-run Preline's auto-init after React renders new markup.
export function usePreline(deps = []) {
  useEffect(() => {
    const id = requestAnimationFrame(() => prelineInit())
    return () => cancelAnimationFrame(id)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps)
}

export function openModal(id) {
  prelineInit(['overlay'])
  window.HSOverlay?.open(`#${id}`)
}
export function closeModal(id) {
  window.HSOverlay?.close(`#${id}`)
}

// ---------- data loading ----------

export function useLoad(loaders, deps = [], { poll } = {}) {
  const [data, setData] = useState(null)
  const [error, setError] = useState('')
  const reload = useCallback(async () => {
    try {
      const keys = Object.keys(loaders)
      const vals = await Promise.all(keys.map((k) => loaders[k]()))
      setData(Object.fromEntries(keys.map((k, i) => [k, vals[i]])))
      setError('')
    } catch (e) {
      setError(e.message)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps)
  useEffect(() => {
    reload()
    if (!poll) return
    const t = setInterval(reload, poll)
    return () => clearInterval(t)
  }, [reload, poll])
  return [data, reload, error]
}

export function useTick(ms = 1000) {
  const [, set] = useState(0)
  useEffect(() => {
    const t = setInterval(() => set((n) => n + 1), ms)
    return () => clearInterval(t)
  }, [ms])
}

// ---------- toasts (global) ----------

export function toast(msg, kind = 'ok') {
  window.dispatchEvent(new CustomEvent('iam:toast', { detail: { msg, kind, id: Math.random() } }))
}

const toastIcon = { ok: CheckCircle2, warn: AlertTriangle, err: XCircle, info: Info }
const toastTone = {
  ok: 'border-emerald-500/30 text-emerald-300',
  warn: 'border-amber-500/30 text-amber-300',
  err: 'border-rose-500/30 text-rose-300',
  info: 'border-sky-500/30 text-sky-300',
}

export function Toaster() {
  const [items, setItems] = useState([])
  useEffect(() => {
    const on = (e) => {
      const t = e.detail
      setItems((xs) => [...xs.slice(-3), t])
      setTimeout(() => setItems((xs) => xs.filter((x) => x.id !== t.id)), 4800)
    }
    window.addEventListener('iam:toast', on)
    return () => window.removeEventListener('iam:toast', on)
  }, [])
  return (
    <div className="pointer-events-none fixed bottom-4 end-4 z-[90] flex w-[min(92vw,380px)] flex-col gap-2" aria-live="polite">
      {items.map((t) => {
        const Icon = toastIcon[t.kind] || Info
        return (
          <div key={t.id} role="status"
            className={`pointer-events-auto flex items-start gap-3 rounded-xl border bg-zinc-900/95 px-4 py-3 text-sm shadow-2xl shadow-black/50 backdrop-blur animate-slide-in ${toastTone[t.kind]}`}>
            <Icon className="mt-0.5 size-4 shrink-0" />
            <span className="text-zinc-200">{t.msg}</span>
            <button className="ms-auto text-zinc-500 hover:text-zinc-200" onClick={() => setItems((xs) => xs.filter((x) => x.id !== t.id))} aria-label="Dismiss">
              <X className="size-4" />
            </button>
          </div>
        )
      })}
    </div>
  )
}

// ---------- dialog (global, Preline overlay) ----------
// ask({ title, message, input: 'text'|'textarea'|false, label, placeholder, required, confirm, tone }) → Promise<string|null>

export function ask(opts) {
  return new Promise((resolve) => window.dispatchEvent(new CustomEvent('iam:ask', { detail: { ...opts, resolve } })))
}

export function DialogHost() {
  const [d, setD] = useState(null)
  const [val, setVal] = useState('')
  const [err, setErr] = useState('')
  const resolved = useRef(false)
  const inputRef = useRef(null)

  useEffect(() => {
    const on = (e) => {
      resolved.current = false
      setD(e.detail)
      setVal(e.detail.defaultValue || '')
      setErr('')
      openModal('iam-dialog')
      setTimeout(() => inputRef.current?.focus(), 250)
    }
    window.addEventListener('iam:ask', on)
    const el = document.getElementById('iam-dialog')
    const onClose = () => {
      setD((cur) => {
        if (cur && !resolved.current) cur.resolve(null)
        return cur
      })
    }
    el?.addEventListener('close.hs.overlay', onClose)
    return () => {
      window.removeEventListener('iam:ask', on)
      el?.removeEventListener('close.hs.overlay', onClose)
    }
  }, [])

  function done(v) {
    if (v !== null && d?.required && !String(v).trim()) {
      setErr(`${d.label || 'A value'} is required`)
      return
    }
    resolved.current = true
    d?.resolve(v)
    closeModal('iam-dialog')
  }

  const tone = d?.tone === 'danger' ? 'danger' : 'primary'
  return (
    <Modal id="iam-dialog" title={d?.title || ''} size="md"
      footer={<>
        <Button variant="ghost" onClick={() => done(null)}>Cancel</Button>
        <Button variant={tone} onClick={() => done(d?.input === false ? 'ok' : val)}>{d?.confirm || 'Confirm'}</Button>
      </>}>
      {d?.message && <div className="text-sm leading-relaxed text-zinc-300">{d.message}</div>}
      {d && d.input !== false && (
        <div className="mt-4">
          {d.label && <label className="label" htmlFor="iam-dialog-input">{d.label}{d.required && <span className="text-rose-400"> *</span>}</label>}
          {d.input === 'text' ? (
            <input id="iam-dialog-input" ref={inputRef} className="input" value={val} placeholder={d.placeholder}
              onChange={(e) => setVal(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && done(val)} />
          ) : (
            <textarea id="iam-dialog-input" ref={inputRef} rows={3} className="input" value={val} placeholder={d.placeholder}
              onChange={(e) => setVal(e.target.value)} />
          )}
          {err && <p className="mt-1.5 text-xs text-rose-400">{err}</p>}
        </div>
      )}
    </Modal>
  )
}

// ---------- primitives ----------

const sizes = { sm: 'sm:max-w-md', md: 'sm:max-w-lg', lg: 'sm:max-w-2xl', xl: 'sm:max-w-4xl' }

export function Modal({ id, title, children, footer, size = 'lg' }) {
  return (
    <div id={id} role="dialog" tabIndex={-1} aria-labelledby={`${id}-label`}
      className="hs-overlay pointer-events-none fixed start-0 top-0 z-[80] hidden size-full overflow-y-auto overflow-x-hidden [--overlay-backdrop:static]"
      data-hs-overlay-keyboard="true">
      <div className={`m-3 mt-0 flex min-h-[calc(100%-3.5rem)] items-center opacity-0 transition-all duration-300 ease-out hs-overlay-open:mt-7 hs-overlay-open:opacity-100 hs-overlay-open:duration-300 sm:mx-auto sm:w-full ${sizes[size]}`}>
        <div className="pointer-events-auto flex w-full flex-col overflow-hidden rounded-2xl border border-white/10 bg-zinc-900 shadow-2xl shadow-black/60">
          <div className="flex items-center justify-between border-b border-white/[0.07] px-5 py-3.5">
            <h3 id={`${id}-label`} className="font-semibold text-zinc-100">{title}</h3>
            <button type="button" aria-label="Close" data-hs-overlay={`#${id}`}
              className="inline-flex size-8 items-center justify-center rounded-full text-zinc-400 transition hover:bg-white/10 hover:text-white">
              <X className="size-4" />
            </button>
          </div>
          <div className="max-h-[70vh] overflow-y-auto p-5">{children}</div>
          {footer && <div className="flex items-center justify-end gap-2 border-t border-white/[0.07] px-5 py-3.5">{footer}</div>}
        </div>
      </div>
    </div>
  )
}

const btn = {
  primary: 'bg-gradient-to-r from-violet-600 to-indigo-600 text-white shadow-lg shadow-violet-900/30 hover:from-violet-500 hover:to-indigo-500',
  ghost: 'border border-white/10 bg-white/[0.03] text-zinc-200 hover:bg-white/[0.08] hover:border-white/20',
  danger: 'bg-rose-600 text-white hover:bg-rose-500 shadow-lg shadow-rose-900/30',
  success: 'bg-emerald-600 text-white hover:bg-emerald-500 shadow-lg shadow-emerald-900/30',
  subtle: 'text-zinc-300 hover:bg-white/[0.06]',
}

export function Button({ variant = 'primary', size = 'md', className = '', children, ...rest }) {
  const sz = size === 'sm' ? 'px-2.5 py-1.5 text-xs gap-1.5' : 'px-4 py-2 text-sm gap-2'
  return (
    <button type="button" {...rest}
      className={`inline-flex items-center justify-center rounded-lg font-semibold transition-all duration-200 active:scale-[0.97] disabled:pointer-events-none disabled:opacity-50 focus:outline-none focus-visible:ring-2 focus-visible:ring-violet-500/60 ${sz} ${btn[variant]} ${className}`}>
      {children}
    </button>
  )
}

const tones = {
  ok: 'bg-emerald-500/10 text-emerald-300 ring-emerald-500/20',
  warn: 'bg-amber-500/10 text-amber-300 ring-amber-500/20',
  bad: 'bg-rose-500/10 text-rose-300 ring-rose-500/20',
  info: 'bg-sky-500/10 text-sky-300 ring-sky-500/20',
  violet: 'bg-violet-500/10 text-violet-300 ring-violet-500/20',
  neutral: 'bg-zinc-500/10 text-zinc-300 ring-zinc-500/20',
}

export function Badge({ tone = 'neutral', children, className = '', dot }) {
  return (
    <span className={`inline-flex items-center gap-1.5 whitespace-nowrap rounded-full px-2 py-0.5 text-[11px] font-semibold ring-1 ring-inset ${tones[tone]} ${className}`}>
      {dot && <span className="size-1.5 rounded-full bg-current" />}
      {children}
    </span>
  )
}

export const levelTone = { low: 'ok', medium: 'warn', high: 'bad', critical: 'bad', none: 'neutral' }

export function Tooltip({ tip, children, className = '' }) {
  return (
    <span className={`hs-tooltip inline-block [--placement:top] ${className}`}>
      <span className="hs-tooltip-toggle inline-flex cursor-help">{children}</span>
      <span role="tooltip"
        className="hs-tooltip-content invisible absolute z-[70] max-w-xs rounded-lg border border-white/10 bg-zinc-800 px-2.5 py-1.5 text-xs font-medium text-zinc-100 opacity-0 shadow-xl transition-opacity hs-tooltip-shown:visible hs-tooltip-shown:opacity-100">
        {tip}
      </span>
    </span>
  )
}

export function PageHeader({ icon: Icon, eyebrow, title, desc, children }) {
  return (
    <header className="mb-6 flex flex-wrap items-end justify-between gap-4 animate-fade-up">
      <div className="max-w-2xl">
        <div className="eyebrow mb-2">{eyebrow}</div>
        <h1 className="flex items-center gap-3 font-display text-2xl font-bold text-white sm:text-3xl">
          {Icon && (
            <span className="inline-flex size-10 items-center justify-center rounded-xl bg-gradient-to-br from-violet-500/20 to-indigo-500/10 ring-1 ring-violet-500/30">
              <Icon className="size-5 text-violet-300" />
            </span>
          )}
          {title}
        </h1>
        {desc && <p className="mt-3 text-sm leading-relaxed text-zinc-400">{desc}</p>}
      </div>
      {children && <div className="flex flex-wrap gap-2">{children}</div>}
    </header>
  )
}

export function Card({ title, subtitle, actions, children, className = '', delay = 0, pad = true }) {
  return (
    <section className={`panel animate-fade-up ${className}`} style={{ animationDelay: `${delay}ms` }}>
      {(title || actions) && (
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-white/[0.06] px-5 py-3.5">
          <div>
            <h2 className="text-sm font-semibold text-zinc-100">{title}</h2>
            {subtitle && <p className="mt-0.5 text-xs text-zinc-500">{subtitle}</p>}
          </div>
          {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
        </div>
      )}
      <div className={pad ? 'p-5' : ''}>{children}</div>
    </section>
  )
}

export function CountUp({ value, duration = 900 }) {
  const [n, setN] = useState(0)
  const from = useRef(0)
  useEffect(() => {
    const start = performance.now(), a = from.current, b = Number(value) || 0
    let raf
    const step = (t) => {
      const p = Math.min(1, (t - start) / duration)
      const eased = 1 - Math.pow(1 - p, 3)
      setN(Math.round(a + (b - a) * eased))
      if (p < 1) raf = requestAnimationFrame(step)
      else from.current = b
    }
    raf = requestAnimationFrame(step)
    return () => cancelAnimationFrame(raf)
  }, [value, duration])
  return <>{n}</>
}

const statTone = {
  violet: 'from-violet-500/20 text-violet-300',
  ok: 'from-emerald-500/20 text-emerald-300',
  warn: 'from-amber-500/20 text-amber-300',
  bad: 'from-rose-500/20 text-rose-300',
  info: 'from-sky-500/20 text-sky-300',
}

export function Stat({ label, value, icon: Icon, tone = 'violet', delay = 0, hint, suffix }) {
  return (
    <div className="panel group relative overflow-hidden p-4 transition-all duration-300 hover:-translate-y-0.5 hover:border-white/15 animate-fade-up"
      style={{ animationDelay: `${delay}ms` }}>
      <div className={`absolute -end-6 -top-6 size-24 rounded-full bg-gradient-to-br to-transparent blur-2xl transition-opacity group-hover:opacity-100 opacity-60 ${statTone[tone]}`} />
      <div className="relative flex items-start justify-between">
        <div>
          <div className="font-display text-2xl font-bold text-white tabular-nums"><CountUp value={value} />{suffix}</div>
          <div className="mt-1 text-xs text-zinc-400">{label}</div>
        </div>
        {Icon && <Icon className={`size-5 ${statTone[tone].split(' ')[1]}`} />}
      </div>
      {hint && <div className="relative mt-2 text-[11px] text-zinc-500">{hint}</div>}
    </div>
  )
}

const barTone = { violet: 'from-violet-500 to-indigo-500', ok: 'from-emerald-500 to-teal-400', warn: 'from-amber-500 to-orange-400', bad: 'from-rose-500 to-pink-500' }

export function Progress({ value, tone = 'violet', className = '' }) {
  const [w, setW] = useState(0)
  useEffect(() => {
    const id = requestAnimationFrame(() => setW(value))
    return () => cancelAnimationFrame(id)
  }, [value])
  return (
    <div className={`h-1.5 w-full overflow-hidden rounded-full bg-white/[0.06] ${className}`} role="progressbar" aria-valuenow={value} aria-valuemin={0} aria-valuemax={100}>
      <div className={`h-full rounded-full bg-gradient-to-r ${barTone[tone]} transition-[width] duration-1000 ease-out`} style={{ width: `${w}%` }} />
    </div>
  )
}

export function Ring({ value, total, size = 120, label }) {
  const pct = total ? value / total : 0
  const r = 52, c = 2 * Math.PI * r
  const [off, setOff] = useState(c)
  useEffect(() => {
    const id = requestAnimationFrame(() => setOff(c * (1 - pct)))
    return () => cancelAnimationFrame(id)
  }, [pct, c])
  const color = pct >= 0.85 ? '#34d399' : pct >= 0.6 ? '#fbbf24' : '#fb7185'
  return (
    <div className="relative inline-flex items-center justify-center" style={{ width: size, height: size }}>
      <svg viewBox="0 0 120 120" className="-rotate-90" width={size} height={size} aria-hidden>
        <circle cx="60" cy="60" r={r} stroke="rgba(255,255,255,0.07)" strokeWidth="10" fill="none" />
        <circle cx="60" cy="60" r={r} stroke={color} strokeWidth="10" fill="none" strokeLinecap="round"
          strokeDasharray={c} strokeDashoffset={off} style={{ transition: 'stroke-dashoffset 1.2s cubic-bezier(.22,1,.36,1)' }} />
      </svg>
      <div className="absolute text-center">
        <div className="font-display text-2xl font-bold text-white tabular-nums"><CountUp value={value} />/{total}</div>
        {label && <div className="text-[10px] uppercase tracking-wider text-zinc-500">{label}</div>}
      </div>
    </div>
  )
}

export function Field({ label, children, hint, required }) {
  return (
    <div>
      <label className="label">{label}{required && <span className="text-rose-400"> *</span>}</label>
      {children}
      {hint && <p className="mt-1 text-[11px] text-zinc-500">{hint}</p>}
    </div>
  )
}

export function ErrorBox({ error }) {
  if (!error) return null
  return (
    <div className="mb-4 flex items-center gap-2 rounded-xl border border-rose-500/30 bg-rose-500/10 px-4 py-3 text-sm text-rose-300 animate-fade-in">
      <XCircle className="size-4" /> API error: {error}
    </div>
  )
}

export function Loading({ rows = 4 }) {
  return (
    <div className="space-y-4" aria-busy="true">
      <div className="skeleton h-10 w-72" />
      <div className="grid gap-4 sm:grid-cols-3">{[0, 1, 2].map((i) => <div key={i} className="skeleton h-24" />)}</div>
      {Array.from({ length: rows }).map((_, i) => <div key={i} className="skeleton h-12" />)}
    </div>
  )
}

export function Empty({ icon: Icon = Info, children }) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 py-10 text-center text-sm text-zinc-500">
      <Icon className="size-6 text-zinc-600" />
      {children}
    </div>
  )
}

export function Avatar({ name, size = 'size-8' }) {
  const initials = (name || '?').split(' ').map((p) => p[0]).slice(0, 2).join('')
  const hue = [...(name || '')].reduce((a, c) => a + c.charCodeAt(0), 0) % 360
  return (
    <span className={`inline-flex ${size} shrink-0 items-center justify-center rounded-full text-[11px] font-bold text-white ring-2 ring-zinc-900`}
      style={{ background: `linear-gradient(135deg, hsl(${hue} 70% 45%), hsl(${(hue + 40) % 360} 70% 35%))` }}>
      {initials}
    </span>
  )
}

export function Seg({ value, onChange, options }) {
  return (
    <div className="inline-flex rounded-lg border border-white/10 bg-zinc-950/60 p-0.5">
      {options.map((o) => (
        <button key={o.value ?? o} type="button" onClick={() => onChange(o.value ?? o)}
          className={`rounded-md px-3 py-1.5 text-xs font-semibold capitalize transition-all ${value === (o.value ?? o) ? 'bg-white/10 text-white shadow' : 'text-zinc-400 hover:text-zinc-200'}`}>
          {o.label ?? o}
        </button>
      ))}
    </div>
  )
}
