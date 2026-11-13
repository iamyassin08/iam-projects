import { useEffect, useState } from 'react'
import {
  ShieldCheck, LayoutDashboard, Users, KeyRound, ClipboardCheck, Timer, Grid3x3, Network, Plug, Radar, ScrollText,
  FlaskConical, Menu, Github, ExternalLink, BookOpen, Fingerprint, Smartphone, Vault as VaultIcon, Cloud as CloudIcon, Activity, Terminal, LogIn, PanelLeftClose, PanelLeftOpen, LifeBuoy, ChevronDown, LogOut, UserRound, Settings2, AlertTriangle,
} from 'lucide-react'
import { Toaster, DialogHost, usePreline, closeModal, Badge, toast } from './ui.jsx'
import { useMe, refreshMe, displayName } from './me.js'
import { UserAvatar } from './components.jsx'
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
import Guide from './pages/Guide.jsx'
import Help from './pages/Help.jsx'
import SSO from './pages/SSO.jsx'
import MFA from './pages/MFA.jsx'
import Vault from './pages/Vault.jsx'
import Cloud from './pages/Cloud.jsx'
import Monitoring from './pages/Monitoring.jsx'
import Automation from './pages/Automation.jsx'
import SignIn from './pages/SignIn.jsx'
import Login from './pages/Login.jsx'
import Profile from './pages/Profile.jsx'
import { api } from './api.js'

export const NAV = [
  {
    group: 'Overview', items: [
      { id: 'home', label: 'Security posture', icon: LayoutDashboard, page: Overview },
      { id: 'guide', label: 'Project guide (start here)', icon: BookOpen, page: Guide },
      { id: 'help', label: 'Help & lab guides', icon: LifeBuoy, page: Help },
      { id: 'profile', label: 'My profile', icon: UserRound, page: Profile },
    ],
  },
  {
    group: 'Lifecycle', items: [
      { id: 'jml', label: 'Joiner · Mover · Leaver', icon: Users, page: JML },
      { id: 'scim', label: 'SCIM 2.0 provisioning', icon: Plug, page: SCIM },
      { id: 'automation', label: 'Automation (Python)', icon: Terminal, page: Automation },
    ],
  },
  {
    group: 'Authentication', items: [
      { id: 'sso', label: 'Single sign-on & Keycloak', icon: Fingerprint, page: SSO },
      { id: 'mfa', label: 'MFA & Conditional Access', icon: Smartphone, page: MFA },
    ],
  },
  {
    group: 'Governance', items: [
      { id: 'requests', label: 'Access requests', icon: KeyRound, page: Requests },
      { id: 'certifications', label: 'Access reviews', icon: ClipboardCheck, page: Certifications },
      { id: 'roles', label: 'Role matrix (RBAC)', icon: Grid3x3, page: RoleMatrix },
    ],
  },
  {
    group: 'Privileged & cloud', items: [
      { id: 'pam', label: 'Just-in-time access', icon: Timer, page: PAM },
      { id: 'vault', label: 'Credential vault', icon: VaultIcon, page: Vault },
      { id: 'cloud', label: 'Cloud IAM (AWS · Azure)', icon: CloudIcon, page: Cloud },
    ],
  },
  {
    group: 'Posture & audit', items: [
      { id: 'monitoring', label: 'Identity threat detection', icon: Activity, page: Monitoring },
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

function SideNav({ hash, collapsed }) {
  return (
    <nav className="flex h-full flex-col">
      <div className={`flex items-center gap-2 py-5 ${collapsed ? 'flex-col px-2' : 'px-5'}`}>
        <a href="#" className="flex min-w-0 flex-1 items-center gap-2.5" title="IAM Projects">
          <span className="relative inline-flex size-9 shrink-0 items-center justify-center rounded-xl bg-gradient-to-br from-violet-500 to-indigo-600 shadow-lg shadow-violet-900/40">
            <ShieldCheck className="size-5 text-white" />
            <span className="absolute -end-0.5 -top-0.5 size-2.5 rounded-full bg-emerald-400 ring-2 ring-zinc-950">
              <span className="absolute inset-0 rounded-full bg-emerald-400 animate-ping-slow" />
            </span>
          </span>
          {!collapsed && <span className="min-w-0">
            <span className="block font-display text-sm font-bold text-white">IAM Projects</span>
            <span className="block truncate text-[10px] uppercase tracking-[0.16em] text-zinc-500">Identity governance lab</span>
          </span>}
        </a>
        <button type="button" data-hs-overlay="#sidebar" aria-label="Close navigation"
          className="inline-flex size-8 shrink-0 items-center justify-center rounded-lg text-zinc-400 hover:bg-white/[0.06] hover:text-white lg:hidden">
          <PanelLeftClose className="size-4" />
        </button>
      </div>
      <div className={`flex-1 space-y-5 overflow-y-auto pb-6 ${collapsed ? 'px-2' : 'px-3'}`}>
        {NAV.map((g) => (
          <div key={g.group}>
            {collapsed ? <div className="mx-2 mb-1.5 border-t border-white/[0.06]" /> : <div className="eyebrow px-2 pb-1.5">{g.group}</div>}
            <ul className="space-y-0.5">
              {g.items.map(({ id, label, icon: Icon }) => {
                const active = hash === id
                return (
                  <li key={id}>
                    <a href={`#${id === 'home' ? '' : id}`} title={collapsed ? label : undefined} aria-label={label}
                      className={`group relative flex items-center gap-2.5 rounded-lg py-2 text-[13px] font-medium transition-all duration-200 ${collapsed ? 'justify-center px-0' : 'px-2.5'} ${active ? 'bg-white/[0.07] text-white' : 'text-zinc-400 hover:bg-white/[0.04] hover:text-zinc-100'}`}>
                      {active && <span className="absolute inset-y-1.5 start-0 w-0.5 rounded-full bg-gradient-to-b from-violet-400 to-indigo-500 animate-fade-in" />}
                      <Icon className={`size-4 shrink-0 transition-colors ${active ? 'text-violet-300' : 'text-zinc-500 group-hover:text-zinc-300'}`} />
                      {!collapsed && label}
                    </a>
                  </li>
                )
              })}
            </ul>
          </div>
        ))}
      </div>
      {!collapsed && <div className="border-t border-white/[0.06] p-4 text-[11px] text-zinc-500">
        <a href="https://github.com/iamyassin08/iam-projects" target="_blank" rel="noreferrer" className="flex items-center gap-2 hover:text-zinc-300">
          <Github className="size-3.5" /> Source on GitHub <ExternalLink className="size-3" />
        </a>
        <div className="mt-1.5">React · Tailwind · Preline · Go 1.24 · OIDC</div>
      </div>}
    </nav>
  )
}

function MenuLink({ href, icon: Icon, children, hint, onClick }) {
  return (
    <a href={href} onClick={onClick} className="flex items-center gap-2.5 rounded-lg px-2.5 py-2 text-zinc-300 hover:bg-white/[0.06] hover:text-white">
      <Icon className="size-4 text-zinc-500" /><span className="flex-1">{children}</span>{hint && <span className="text-[10px] text-zinc-500">{hint}</span>}
    </a>
  )
}

function AccountMenu() {
  const me = useMe()
  const [open, setOpen] = useState(false)
  useEffect(() => {
    if (!open) return
    const close = (e) => { if (!e.target.closest?.('[data-account]')) setOpen(false) }
    const esc = (e) => e.key === 'Escape' && setOpen(false)
    document.addEventListener('click', close)
    document.addEventListener('keydown', esc)
    return () => { document.removeEventListener('click', close); document.removeEventListener('keydown', esc) }
  }, [open])
  useEffect(() => { const on = () => setOpen(false); window.addEventListener('hashchange', on); return () => window.removeEventListener('hashchange', on) }, [])
  if (!me) return <span className="skeleton block h-8 w-24 rounded-lg" />

  const authed = me.authenticated
  const kc = me.providers?.find((p) => p.id === 'keycloak')
  const groups = me.user?.g || []
  const isAdmin = groups.includes('iam-admins') || groups.includes('iam-admin')
  const hasMFA = (me.user?.amr || []).some((a) => a === 'mfa' || a === 'otp')
  const close = () => setOpen(false)
  async function signOut() { await api.logout(); window.location.hash = 'login'; await refreshMe(); toast('Signed out') }
  async function everywhere() { await api.signOutEverywhere(); window.location.hash = 'login'; await refreshMe(); toast('Signed out of every session') }

  return (
    <div className="relative" data-account>
      {authed ? (
        <button type="button" onClick={() => setOpen(!open)} aria-expanded={open} aria-haspopup="menu" aria-label="Account menu"
          className="flex items-center gap-2 rounded-full border border-white/10 bg-white/[0.03] py-1 pe-2.5 ps-1 text-xs font-semibold text-zinc-200 transition hover:border-white/20 hover:bg-white/[0.06]">
          <span className="relative"><UserAvatar me={me} />{!hasMFA && <span className="absolute -end-0.5 -top-0.5 size-2 rounded-full bg-amber-400 ring-2 ring-zinc-950" title="Signed in without MFA" />}</span>
          <span className="hidden max-w-32 truncate sm:inline">{displayName(me)}</span>
          <ChevronDown className={`size-3.5 text-zinc-500 transition ${open ? 'rotate-180' : ''}`} />
        </button>
      ) : (
        <div className="flex items-center gap-1">
          <a href="#login" className="flex items-center gap-2 rounded-lg bg-gradient-to-r from-violet-600 to-indigo-600 px-3 py-1.5 text-xs font-semibold text-white shadow-lg shadow-violet-900/30 hover:from-violet-500 hover:to-indigo-500">
            <LogIn className="size-3.5" /><span className="whitespace-nowrap">Sign in</span>
          </a>
          <button type="button" onClick={() => setOpen(!open)} aria-expanded={open} aria-haspopup="menu" aria-label="Sign-in options"
            className="inline-flex size-8 items-center justify-center rounded-lg border border-white/10 text-zinc-400 hover:bg-white/5 hover:text-zinc-200"><ChevronDown className="size-4" /></button>
        </div>
      )}

      {open && (
        <div role="menu" className="absolute end-0 top-full z-50 mt-2 w-72 overflow-hidden rounded-2xl border border-white/10 bg-zinc-900/95 text-sm shadow-2xl shadow-black/60 backdrop-blur animate-scale-in">
          {authed ? (<>
            <div className="flex items-center gap-3 border-b border-white/[0.06] p-4">
              <UserAvatar me={me} size="size-11" text="text-sm" />
              <div className="min-w-0">
                <div className="truncate font-semibold text-white">{displayName(me)}</div>
                <div className="truncate text-xs text-zinc-500">{me.user.e || me.user.u}</div>
                <div className="mt-1.5 flex flex-wrap gap-1">
                  <Badge tone="info">{me.user.idp === 'keycloak' ? 'Keycloak' : 'Built-in IdP'}</Badge>
                  {isAdmin && <Badge tone="violet">Admin</Badge>}
                  {hasMFA ? <Badge tone="ok">MFA</Badge> : <Badge tone="warn">No MFA</Badge>}
                </div>
              </div>
            </div>
            {!hasMFA && (
              <a href="#mfa" onClick={close} className="mx-2 mt-2 flex items-start gap-2 rounded-lg border border-amber-500/25 bg-amber-500/10 px-2.5 py-2 text-xs text-amber-200">
                <AlertTriangle className="mt-0.5 size-3.5 shrink-0" />This session didn't use MFA. CA002 is report-only, so it was allowed. See why.
              </a>
            )}
            <div className="p-2">
              <MenuLink href="#profile" icon={UserRound} onClick={close}>My profile</MenuLink>
              <MenuLink href="#profile?tab=access" icon={KeyRound} onClick={close} hint={me.profile ? '' : ''}>My access</MenuLink>
              <MenuLink href="#profile?tab=security" icon={ShieldCheck} onClick={close}>Security & sessions</MenuLink>
              <MenuLink href="#profile?tab=activity" icon={Activity} onClick={close}>My activity</MenuLink>
              <MenuLink href="#profile?tab=preferences" icon={Settings2} onClick={close}>Preferences</MenuLink>
              <MenuLink href="#sso" icon={Fingerprint} onClick={close}>View my tokens</MenuLink>
              {isAdmin && <MenuLink href="#lab" icon={FlaskConical} onClick={close} hint="admin">Controls lab</MenuLink>}
            </div>
            <div className="border-t border-white/[0.06] p-2">
              <MenuLink href="#help" icon={LifeBuoy} onClick={close}>Help & lab guides</MenuLink>
              <button type="button" onClick={signOut} className="flex w-full items-center gap-2.5 rounded-lg px-2.5 py-2 text-start text-rose-300 hover:bg-rose-500/10"><LogOut className="size-4" />Sign out</button>
              <button type="button" onClick={everywhere} className="flex w-full items-center gap-2.5 rounded-lg px-2.5 py-2 text-start text-xs text-zinc-500 hover:bg-white/[0.04] hover:text-zinc-300"><LogOut className="size-3.5" />Sign out everywhere</button>
            </div>
          </>) : (
            <div className="p-2">
              <div className="px-2.5 pb-1.5 pt-1 text-[11px] text-zinc-500">Single sign-on with MFA · password <span className="font-mono text-zinc-300">test123</span></div>
              <a href="/auth/login" className="block rounded-lg px-2.5 py-2 hover:bg-white/5"><div className="font-medium text-zinc-100">Assafwah IdP (built-in)</div><div className="text-[11px] text-zinc-500">Demo authenticator included</div></a>
              {kc?.configured
                ? <a href="/auth/login?idp=keycloak" className="block rounded-lg px-2.5 py-2 hover:bg-white/5"><div className="font-medium text-zinc-100">Keycloak</div><div className="text-[11px] text-zinc-500">keycloak.assafwahinc.com</div></a>
                : <div className="rounded-lg px-2.5 py-2 opacity-50"><div className="font-medium text-zinc-100">Keycloak</div><div className="text-[11px] text-zinc-500">Not connected on this deployment</div></div>}
              <div className="mt-1 border-t border-white/[0.06] pt-1">
                <MenuLink href="#login" icon={UserRound} onClick={close}>All sign-in options & demo accounts</MenuLink>
                <MenuLink href="#help" icon={LifeBuoy} onClick={close}>Help & lab guides</MenuLink>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

function TopBar({ title, collapsed, onToggle }) {
  return (
    <div className="sticky top-0 z-40 flex items-center gap-3 border-b border-white/[0.06] bg-zinc-950/80 px-4 py-2.5 backdrop-blur sm:px-6">
      <button type="button" aria-label="Open navigation" aria-controls="sidebar" data-hs-overlay="#sidebar"
        className="inline-flex size-9 items-center justify-center rounded-lg border border-white/10 text-zinc-300 hover:bg-white/5 lg:hidden">
        <Menu className="size-4" />
      </button>
      <button type="button" onClick={onToggle} aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'} title={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
        className="hidden size-9 items-center justify-center rounded-lg border border-white/10 text-zinc-300 hover:bg-white/5 lg:inline-flex">
        {collapsed ? <PanelLeftOpen className="size-4" /> : <PanelLeftClose className="size-4" />}
      </button>
      <span className="min-w-0 truncate text-sm font-semibold text-zinc-200"><span className="hidden sm:inline lg:hidden">IAM Projects · </span>{title}</span>
      <div className="ms-auto"><AccountMenu /></div>
    </div>
  )
}

function useCollapsed() {
  const [c, setC] = useState(() => { try { return localStorage.getItem('iam.sidebar') === 'collapsed' } catch { return false } })
  const [desktop, setDesktop] = useState(() => window.matchMedia('(min-width: 1024px)').matches)
  useEffect(() => {
    const mq = window.matchMedia('(min-width: 1024px)')
    const on = () => setDesktop(mq.matches)
    mq.addEventListener('change', on)
    return () => mq.removeEventListener('change', on)
  }, [])
  useEffect(() => {
    const on = () => { try { setC(localStorage.getItem('iam.sidebar') === 'collapsed') } catch { /* ignore */ } }
    window.addEventListener('iam:sidebar', on)
    return () => window.removeEventListener('iam:sidebar', on)
  }, [])
  const toggle = () => setC((v) => { try { localStorage.setItem('iam.sidebar', v ? 'open' : 'collapsed') } catch { /* private mode */ } return !v })
  return [c && desktop, toggle]
}

export default function App() {
  const hash = useHash()
  const [collapsed, toggleCollapsed] = useCollapsed()
  const current = ALL.find((n) => n.id === hash) || ALL[0]
  const Page = hash === 'login' ? Login : current.page
  const title = hash === 'login' ? 'Sign in' : current.label
  usePreline([hash])

  useEffect(() => { document.title = hash === 'login' ? 'Sign in · IAM Projects' : hash === 'signin' ? 'Sign in · Assafwah IdP' : `${current.label} · IAM Projects` }, [current, hash])

  if (hash === 'signin') return <><SignIn /><Toaster /></>

  return (
    <div className="relative min-h-screen">
      {/* ambient background */}
      <div aria-hidden className="pointer-events-none fixed inset-0 -z-10 overflow-hidden">
        <div className="grid-bg absolute inset-0 [mask-image:radial-gradient(ellipse_at_top,black_20%,transparent_70%)]" />
        <div className="absolute -top-40 start-1/3 h-96 w-[42rem] rounded-full bg-violet-600/20 blur-[120px] animate-glow" />
        <div className="absolute top-1/2 -end-40 h-80 w-96 rounded-full bg-indigo-600/10 blur-[120px]" />
      </div>

      {/* sidebar: Preline offcanvas on mobile, fixed on desktop */}
      <aside id="sidebar" tabIndex={-1} aria-label="Sidebar"
        className={`hs-overlay hs-overlay-open:translate-x-0 fixed inset-y-0 start-0 z-[60] hidden w-64 -translate-x-full transform ${collapsed ? 'lg:w-16' : 'lg:w-64'} border-e border-white/[0.06] bg-zinc-950/95 backdrop-blur transition-all duration-300 lg:bottom-0 lg:end-auto lg:block lg:translate-x-0`}>
        <SideNav hash={hash} collapsed={collapsed} />
      </aside>

      <main className={`transition-[padding] duration-300 ${collapsed ? 'lg:ps-16' : 'lg:ps-64'}`}>
        <TopBar title={title} collapsed={collapsed} onToggle={toggleCollapsed} />
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
