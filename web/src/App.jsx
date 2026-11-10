import { useEffect, useState } from 'react'
import {
  ShieldCheck, LayoutDashboard, Users, KeyRound, ClipboardCheck, Timer, Grid3x3, Network, Plug, Radar, ScrollText,
  FlaskConical, Menu, Github, ExternalLink,
} from 'lucide-react'
import { Toaster, DialogHost, usePreline, closeModal } from './ui.jsx'
import Overview from './pages/Overview.jsx'
import JML from './pages/JML.jsx'
import Requests from './pages/Requests.jsx'
import Certifications from './pages/Certifications.jsx'
import PAM from './pages/PAM.jsx'
import RoleMatrix from './pages/RoleMatrix.jsx'
import SystemMap from './pages/SystemMap.jsx'
import SCIM from './pages/SCIM.jsx'
import Risk from './pages/Risk.jsx'
import Audit from './pages/Audit.jsx'
import Lab from './pages/Lab.jsx'

export const NAV = [
  { group: 'Overview', items: [{ id: 'home', label: 'Security posture', icon: LayoutDashboard, page: Overview }] },
  {
    group: 'Lifecycle', items: [
      { id: 'jml', label: 'Joiner · Mover · Leaver', icon: Users, page: JML },
      { id: 'scim', label: 'SCIM 2.0 provisioning', icon: Plug, page: SCIM },
    ],
  },
  {
    group: 'Governance', items: [
      { id: 'requests', label: 'Access requests', icon: KeyRound, page: Requests },
      { id: 'certifications', label: 'Access reviews', icon: ClipboardCheck, page: Certifications },
      { id: 'roles', label: 'Role matrix (RBAC)', icon: Grid3x3, page: RoleMatrix },
    ],
  },
  { group: 'Privileged access', items: [{ id: 'pam', label: 'Just-in-time access', icon: Timer, page: PAM }] },
  {
    group: 'Posture & audit', items: [
      { id: 'risk', label: 'Risk & reconciliation', icon: Radar, page: Risk },
      { id: 'systems', label: 'System map', icon: Network, page: SystemMap },
      { id: 'audit', label: 'Audit log', icon: ScrollText, page: Audit },
      { id: 'lab', label: 'Controls lab', icon: FlaskConical, page: Lab },
    ],
  },
]
const ALL = NAV.flatMap((g) => g.items)

function useHash() {
  const read = () => window.location.hash.replace('#', '').split('?')[0] || 'home'
  const [hash, setHash] = useState(read)
  useEffect(() => {
    const on = () => {
      setHash(read())
      window.scrollTo({ top: 0 })
      closeModal('sidebar')
    }
    window.addEventListener('hashchange', on)
    return () => window.removeEventListener('hashchange', on)
  }, [])
  return hash
}

function SideNav({ hash }) {
  return (
    <nav className="flex h-full flex-col">
      <a href="#" className="flex items-center gap-2.5 px-5 py-5">
        <span className="relative inline-flex size-9 items-center justify-center rounded-xl bg-gradient-to-br from-violet-500 to-indigo-600 shadow-lg shadow-violet-900/40">
          <ShieldCheck className="size-5 text-white" />
          <span className="absolute -end-0.5 -top-0.5 size-2.5 rounded-full bg-emerald-400 ring-2 ring-zinc-950">
            <span className="absolute inset-0 rounded-full bg-emerald-400 animate-ping-slow" />
          </span>
        </span>
        <span>
          <span className="block font-display text-sm font-bold text-white">IAM Projects</span>
          <span className="block text-[10px] uppercase tracking-[0.16em] text-zinc-500">Identity governance lab</span>
        </span>
      </a>
      <div className="flex-1 space-y-5 overflow-y-auto px-3 pb-6">
        {NAV.map((g) => (
          <div key={g.group}>
            <div className="eyebrow px-2 pb-1.5">{g.group}</div>
            <ul className="space-y-0.5">
              {g.items.map(({ id, label, icon: Icon }) => {
                const active = hash === id
                return (
                  <li key={id}>
                    <a href={`#${id === 'home' ? '' : id}`}
                      className={`group relative flex items-center gap-2.5 rounded-lg px-2.5 py-2 text-[13px] font-medium transition-all duration-200 ${active ? 'bg-white/[0.07] text-white' : 'text-zinc-400 hover:bg-white/[0.04] hover:text-zinc-100'}`}>
                      {active && <span className="absolute inset-y-1.5 start-0 w-0.5 rounded-full bg-gradient-to-b from-violet-400 to-indigo-500 animate-fade-in" />}
                      <Icon className={`size-4 transition-colors ${active ? 'text-violet-300' : 'text-zinc-500 group-hover:text-zinc-300'}`} />
                      {label}
                    </a>
                  </li>
                )
              })}
            </ul>
          </div>
        ))}
      </div>
      <div className="border-t border-white/[0.06] p-4 text-[11px] text-zinc-500">
        <a href="https://github.com/iamyassin08/iam-projects" target="_blank" rel="noreferrer" className="flex items-center gap-2 hover:text-zinc-300">
          <Github className="size-3.5" /> Source on GitHub <ExternalLink className="size-3" />
        </a>
        <div className="mt-1.5">React · Tailwind · Preline · Go 1.24</div>
      </div>
    </nav>
  )
}

export default function App() {
  const hash = useHash()
  const current = ALL.find((n) => n.id === hash) || ALL[0]
  const Page = current.page
  usePreline([hash])

  useEffect(() => { document.title = `${current.label} · IAM Projects` }, [current])

  return (
    <div className="relative min-h-screen">
      {/* ambient background */}
      <div aria-hidden className="pointer-events-none fixed inset-0 -z-10 overflow-hidden">
        <div className="grid-bg absolute inset-0 [mask-image:radial-gradient(ellipse_at_top,black_20%,transparent_70%)]" />
        <div className="absolute -top-40 start-1/3 h-96 w-[42rem] rounded-full bg-violet-600/20 blur-[120px] animate-glow" />
        <div className="absolute top-1/2 -end-40 h-80 w-96 rounded-full bg-indigo-600/10 blur-[120px]" />
      </div>

      {/* mobile top bar */}
      <div className="sticky top-0 z-40 flex items-center gap-3 border-b border-white/[0.06] bg-zinc-950/80 px-4 py-3 backdrop-blur lg:hidden">
        <button type="button" aria-label="Open navigation" aria-controls="sidebar" data-hs-overlay="#sidebar"
          className="inline-flex size-9 items-center justify-center rounded-lg border border-white/10 text-zinc-300 hover:bg-white/5">
          <Menu className="size-4" />
        </button>
        <span className="flex items-center gap-2 font-display text-sm font-bold text-white"><ShieldCheck className="size-4 text-violet-400" /> IAM Projects</span>
      </div>

      {/* sidebar: Preline offcanvas on mobile, fixed on desktop */}
      <aside id="sidebar" tabIndex={-1} aria-label="Sidebar"
        className="hs-overlay hs-overlay-open:translate-x-0 fixed inset-y-0 start-0 z-[60] hidden w-64 -translate-x-full transform border-e border-white/[0.06] bg-zinc-950/95 backdrop-blur transition-all duration-300 lg:bottom-0 lg:end-auto lg:block lg:translate-x-0">
        <SideNav hash={hash} />
      </aside>

      <main className="lg:ps-64">
        <div key={hash} className="mx-auto max-w-7xl px-4 py-6 sm:px-6 lg:px-8 lg:py-8">
          <Page />
        </div>
        <footer className="border-t border-white/[0.06] px-6 py-5 text-center text-xs text-zinc-500 lg:ps-0">
          All people and data are fictional. Product names only label the type of system being simulated. Built by Yassin.
        </footer>
      </main>

      <Toaster />
      <DialogHost />
    </div>
  )
}
