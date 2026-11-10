import { useEffect, useState } from 'react'
import {
  ShieldCheck, Users, KeyRound, Grid3x3, Network, ScrollText, FlaskConical, RotateCcw, ArrowRight,
} from 'lucide-react'
import { api } from './api.js'
import { useLoad, useToast } from './hooks.js'
import { Toast } from './ui.jsx'
import JML from './pages/JML.jsx'
import Requests from './pages/Requests.jsx'
import RoleMatrix from './pages/RoleMatrix.jsx'
import SystemMap from './pages/SystemMap.jsx'
import Audit from './pages/Audit.jsx'
import Lab from './pages/Lab.jsx'

const NAV = [
  { id: 'jml', label: 'JML workflow', icon: Users, page: JML },
  { id: 'requests', label: 'Access requests', icon: KeyRound, page: Requests },
  { id: 'roles', label: 'Role matrix', icon: Grid3x3, page: RoleMatrix },
  { id: 'systems', label: 'System map', icon: Network, page: SystemMap },
  { id: 'audit', label: 'Audit log', icon: ScrollText, page: Audit },
  { id: 'lab', label: 'Lab guide', icon: FlaskConical, page: Lab },
]

const CARDS = [
  { id: 'jml', job: 'Identity lifecycle', text: 'Onboard, transfer and terminate. Birthright access follows the role automatically.' },
  { id: 'requests', job: 'Request & approval', text: 'Ask for access outside your role. SoD conflicts are flagged and need a risk acceptance.' },
  { id: 'roles', job: 'RBAC · least privilege', text: 'Roles × entitlements. Toggle a cell and every active member is re-synced.' },
  { id: 'systems', job: 'App inventory', text: 'HR source → IdP → directory and apps, with protocol, provisioning, owner and users.' },
]

function useHash() {
  const read = () => window.location.hash.replace('#', '') || 'home'
  const [hash, setHash] = useState(read)
  useEffect(() => {
    const on = () => { setHash(read()); window.scrollTo(0, 0) }
    window.addEventListener('hashchange', on)
    return () => window.removeEventListener('hashchange', on)
  }, [])
  return hash
}

function Home() {
  const [data, reload, error] = useLoad({ summary: api.summary })
  const [toast, show] = useToast()
  const s = data?.summary

  async function reset() {
    if (!confirm('Reset all demo data back to the seed tenant?')) return
    try { await api.reset(); await reload(); show('Demo tenant reset') } catch (e) { show(e.message, 'err') }
  }

  const stats = s ? [
    ['Active identities', s.activeIdentities], ['Pending requests', s.pendingRequests],
    ['Roles', s.roles], ['Systems', s.systems], ['Grants', s.grants], ['Privileged grants', s.privilegedGrants],
  ] : []

  return (
    <div className="home">
      <section className="hero">
        <div className="eyebrow">Mini IAM lab</div>
        <h1>IAM <span className="accent">Projects</span></h1>
        <p className="lede">
          A small, working Identity &amp; Access Management platform covering the four everyday jobs of an
          IAM analyst: lifecycle, request governance, role design and system inventory.
        </p>
        <div className="hero-actions">
          <a className="btn primary" href="#lab"><FlaskConical size={16} /> Open the lab guide</a>
          <button className="btn ghost" onClick={reset}><RotateCcw size={16} /> Reset demo data</button>
        </div>
      </section>

      {error && <div className="error-box">API unreachable: {error}</div>}

      <section className="stats">
        {stats.map(([label, n]) => (
          <div className="stat" key={label}><div className="stat-n">{n}</div><div className="stat-l">{label}</div></div>
        ))}
      </section>

      <section className="cards">
        {CARDS.map((c) => {
          const n = NAV.find((x) => x.id === c.id)
          const Icon = n.icon
          return (
            <a className="card project" key={c.id} href={`#${c.id}`}>
              <Icon size={28} className="card-icon" />
              <div className="eyebrow">{c.job}</div>
              <h2>{n.label}</h2>
              <p>{c.text}</p>
              <span className="card-go">Open <ArrowRight size={14} /></span>
            </a>
          )
        })}
      </section>

      <p className="muted small center">
        All people and data are fictional. Product names only label the type of system being simulated.
      </p>
      <Toast toast={toast} />
    </div>
  )
}

export default function App() {
  const hash = useHash()
  const current = NAV.find((n) => n.id === hash)
  const Page = current?.page || Home

  return (
    <div className="shell">
      <nav className="topnav">
        <a href="#" className="brand"><ShieldCheck size={22} /> <span>IAM Projects</span></a>
        <div className="navlinks">
          {NAV.map(({ id, label, icon: Icon }) => (
            <a key={id} href={`#${id}`} className={hash === id ? 'active' : ''}>
              <Icon size={15} /> <span>{label}</span>
            </a>
          ))}
        </div>
      </nav>
      <main className="content"><Page /></main>
      <footer className="foot">IAM Projects · React + Go · built by Yassin</footer>
    </div>
  )
}
