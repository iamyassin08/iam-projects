// Small shared UI pieces.
export function PageHead({ icon: Icon, title, job, children }) {
  return (
    <header className="page-head">
      <div>
        <div className="eyebrow">{job}</div>
        <h1>{Icon && <Icon size={26} />} {title}</h1>
      </div>
      <div className="page-actions">{children}</div>
    </header>
  )
}

export function Toast({ toast }) {
  if (!toast) return null
  return <div className={`toast ${toast.kind}`} role="status">{toast.msg}</div>
}

export function Badge({ kind = 'neutral', children }) {
  return <span className={`badge ${kind}`}>{children}</span>
}

export function ErrorBox({ error }) {
  return error ? <div className="error-box">API error: {error}</div> : null
}

export function Loading() {
  return <div className="muted pad">Loading…</div>
}

export function Field({ label, children }) {
  return (
    <label className="field">
      <span>{label}</span>
      {children}
    </label>
  )
}
