import { useState } from 'react'
import { BookOpen, ExternalLink, Copy, Check, Mic, FileText, Wrench, Monitor, Lightbulb, ListChecks, Award, Printer } from 'lucide-react'
import { Card, Badge, Button, Seg, toast } from '../ui.jsx'
import { Flow } from '../components.jsx'
import { PROJECTS, PITCH, KEYWORDS, CERTS } from '../guide.js'

function Copyable({ text, label = 'Copy' }) {
  const [done, setDone] = useState(false)
  return (
    <Button size="sm" variant="ghost" onClick={async () => { try { await navigator.clipboard.writeText(text); setDone(true); setTimeout(() => setDone(false), 1400) } catch { toast('Copy failed', 'err') } }}>
      {done ? <Check className="size-3.5" /> : <Copy className="size-3.5" />}{done ? 'Copied' : label}
    </Button>
  )
}

const TABS = [
  { value: 'what', label: 'What it is', icon: Lightbulb },
  { value: 'looks', label: 'How it looks', icon: Monitor },
  { value: 'built', label: 'How I built it', icon: Wrench },
  { value: 'real', label: 'Do it in Entra / AWS', icon: ListChecks },
  { value: 'interview', label: 'Interview', icon: Mic },
  { value: 'resume', label: 'Resume line', icon: FileText },
]

function Project({ p }) {
  const [tab, setTab] = useState('what')
  return (
    <section id={`p-${p.n}`} className="panel scroll-mt-6 overflow-hidden animate-fade-up">
      <div className="flex flex-wrap items-start gap-4 border-b border-white/[0.06] px-5 py-4">
        <span className="inline-flex size-11 shrink-0 items-center justify-center rounded-xl bg-gradient-to-br from-violet-500 to-indigo-600 font-display text-lg font-bold text-white shadow-lg shadow-violet-900/40">{p.n}</span>
        <div className="min-w-0 flex-1">
          <h2 className="font-display text-lg font-bold text-white">{p.title}</h2>
          <div className="mt-1.5 flex flex-wrap gap-1.5">{p.skills.map((s) => <Badge key={s} tone="violet">{s}</Badge>)}</div>
        </div>
        <div className="flex flex-wrap gap-2">
          {p.modules.map(([id, label]) => <a key={id} href={`#${id}`}><Button size="sm"><ExternalLink className="size-3.5" />{label}</Button></a>)}
        </div>
      </div>
      <div className="border-b border-white/[0.06] px-5 py-2.5 overflow-x-auto"><Seg value={tab} onChange={setTab} options={TABS.map((t) => ({ value: t.value, label: t.label }))} /></div>

      <div key={tab} className="p-5 animate-fade-in">
        {tab === 'what' && (
          <div className="space-y-4">
            <p className="max-w-3xl text-sm leading-relaxed text-zinc-300">{p.what}</p>
            <Flow nodes={p.flow} />
            <div className="flex flex-wrap gap-2">{p.controls.map((c) => <Badge key={c} tone="ok" dot>{c}</Badge>)}</div>
          </div>
        )}
        {tab === 'looks' && (
          <div className="grid gap-5 lg:grid-cols-5">
            <a href={`#${p.modules[0][0]}`} className="group block overflow-hidden rounded-xl border border-white/10 lg:col-span-3">
              <img src={`/guide/${p.shot}.jpg`} alt={`Screenshot: ${p.title}`} loading="lazy" className="w-full transition duration-500 group-hover:scale-[1.02]" />
            </a>
            <div className="lg:col-span-2">
              <div className="eyebrow mb-2">Try it in two minutes</div>
              <ol className="space-y-2">
                {p.tryIt.map((s, i) => (
                  <li key={i} className="flex gap-3 text-sm text-zinc-300"><span className="inline-flex size-6 shrink-0 items-center justify-center rounded-full bg-violet-500/15 text-xs font-bold text-violet-300">{i + 1}</span>{s}</li>
                ))}
              </ol>
            </div>
          </div>
        )}
        {tab === 'built' && (
          <ul className="space-y-2.5">
            {p.built.map((b, i) => <li key={i} className="flex gap-3 text-sm leading-relaxed text-zinc-300"><Check className="mt-0.5 size-4 shrink-0 text-emerald-400" />{b}</li>)}
          </ul>
        )}
        {tab === 'real' && (
          <div>
            <p className="mb-3 text-xs text-zinc-500">The same project on the platforms employers use. Do these in a free tenant and screenshot each step for your portfolio.</p>
            <ol className="space-y-2.5">
              {p.real.map((s, i) => <li key={i} className="flex gap-3 text-sm leading-relaxed text-zinc-300"><span className="inline-flex size-6 shrink-0 items-center justify-center rounded-full bg-sky-500/15 text-xs font-bold text-sky-300">{i + 1}</span>{s}</li>)}
            </ol>
          </div>
        )}
        {tab === 'interview' && (
          <div className="grid gap-5 lg:grid-cols-2">
            <div>
              <div className="eyebrow mb-2">STAR story</div>
              <dl className="space-y-2.5 text-sm">
                {[['Situation', p.star.s], ['Task', p.star.t], ['Action', p.star.a], ['Result', p.star.r]].map(([k, v]) => (
                  <div key={k} className="rounded-xl border border-white/[0.07] bg-white/[0.02] p-3"><dt className="text-[11px] font-bold uppercase tracking-wider text-violet-300">{k}</dt><dd className="mt-1 leading-relaxed text-zinc-300">{v}</dd></div>
                ))}
              </dl>
            </div>
            <div>
              <div className="eyebrow mb-2">Questions you'll likely get</div>
              <div className="space-y-2.5">
                {p.qa.map(([q, a]) => (
                  <details key={q} className="group rounded-xl border border-white/[0.07] bg-white/[0.02] p-3">
                    <summary className="cursor-pointer list-none text-sm font-medium text-zinc-100">{q}<span className="float-end text-zinc-500 group-open:rotate-45 transition">+</span></summary>
                    <p className="mt-2 text-sm leading-relaxed text-zinc-400">{a}</p>
                  </details>
                ))}
              </div>
            </div>
          </div>
        )}
        {tab === 'resume' && (
          <div className="space-y-3">
            <blockquote className="rounded-xl border-s-4 border-violet-500 bg-violet-500/[0.06] p-4 text-sm leading-relaxed text-zinc-100">{p.bullet}</blockquote>
            <Copyable text={p.bullet} label="Copy bullet" />
          </div>
        )}
      </div>
    </section>
  )
}

export default function Guide() {
  const allBullets = PROJECTS.map((p) => `• ${p.bullet}`).join('\n')
  return (
    <div className="space-y-6">
      <section className="relative overflow-hidden rounded-3xl border border-white/[0.07] bg-gradient-to-br from-violet-950/60 via-zinc-900/60 to-zinc-950 p-6 sm:p-10 animate-fade-up">
        <div aria-hidden className="absolute -end-20 -top-20 size-72 rounded-full bg-violet-500/20 blur-3xl animate-glow" />
        <div className="relative">
          <Badge tone="violet" dot>Start here · for recruiters and interviews</Badge>
          <h1 className="mt-4 font-display text-3xl font-extrabold leading-tight text-white sm:text-4xl">
            10 IAM analyst projects, <span className="bg-gradient-to-r from-violet-300 via-indigo-300 to-sky-300 bg-clip-text text-transparent">one working platform</span>
          </h1>
          <p className="mt-4 max-w-3xl text-sm leading-relaxed text-zinc-300 sm:text-base">
            Each project below links to the live module that implements it, shows what it looks like, explains how it was built, lists the same steps on Entra ID, Okta, Keycloak or AWS, and ends with an interview story and a resume line.
          </p>
          <div className="mt-5 rounded-2xl border border-white/10 bg-zinc-950/50 p-4">
            <div className="mb-2 flex items-center justify-between gap-2"><span className="eyebrow">30-second pitch</span><Copyable text={PITCH} /></div>
            <p className="text-sm leading-relaxed text-zinc-200">{PITCH}</p>
          </div>
          <div className="mt-5 flex flex-wrap gap-2 print:hidden">
            <a href="#sso"><Button><ExternalLink className="size-4" /> Sign in and see SSO + MFA live</Button></a>
            <a href="#lab"><Button variant="ghost">Controls lab: 20 audit controls</Button></a>
            <Button variant="subtle" onClick={() => window.print()}><Printer className="size-4" /> Print / PDF</Button>
          </div>
        </div>
      </section>

      <div className="grid grid-cols-2 gap-3 md:grid-cols-5">
        {PROJECTS.map((p, i) => (
          <a key={p.n} href={`#guide`} onClick={(e) => { e.preventDefault(); document.getElementById(`p-${p.n}`)?.scrollIntoView({ behavior: 'smooth' }) }}
            className="panel group p-4 transition hover:-translate-y-0.5 hover:border-violet-500/30 animate-fade-up" style={{ animationDelay: `${i * 40}ms` }}>
            <div className="flex items-center justify-between"><span className="font-display text-xl font-bold text-violet-300">{p.n}</span><Badge tone="ok" dot>built</Badge></div>
            <div className="mt-2 text-sm font-semibold text-zinc-100">{p.title}</div>
            <div className="mt-0.5 text-[11px] text-zinc-500">{p.short}</div>
          </a>
        ))}
      </div>

      {PROJECTS.map((p) => <Project key={p.n} p={p} />)}

      <div className="grid gap-6 lg:grid-cols-2">
        <Card title="All ten resume bullets" subtitle="Pick 4–6 for your resume; keep the rest for LinkedIn" actions={<Copyable text={allBullets} label="Copy all" />}>
          <ul className="space-y-2 text-sm leading-relaxed text-zinc-300">{PROJECTS.map((p) => <li key={p.n} className="flex gap-2"><span className="font-bold text-violet-300">{p.n}.</span>{p.bullet}</li>)}</ul>
        </Card>
        <div className="space-y-6">
          <Card title="ATS keywords covered" subtitle="Terms recruiters and applicant tracking systems scan for">
            <div className="flex flex-wrap gap-1.5">{KEYWORDS.map((k) => <Badge key={k} tone="neutral">{k}</Badge>)}</div>
          </Card>
          <Card title="Certification mapping" subtitle="Where each exam's objectives show up here">
            <ul className="space-y-2.5">{CERTS.map(([c, m]) => <li key={c} className="flex gap-3 text-sm"><Award className="mt-0.5 size-4 shrink-0 text-amber-300" /><div><div className="font-medium text-zinc-100">{c}</div><div className="text-xs text-zinc-400">{m}</div></div></li>)}</ul>
          </Card>
          <Card title="How to present this">
            <ol className="list-decimal space-y-1.5 ps-5 text-sm text-zinc-300">
              <li>Resume: one "Projects" entry linking iam.assafwahinc.com and the GitHub repo, with 4–6 bullets from above.</li>
              <li>Interview: share your screen, open the Controls lab, and fix one finding live (C18 or C15 take a minute).</li>
              <li>LinkedIn: one post per project with its screenshot and the STAR story.</li>
              <li>Be honest about scope: "a working lab I built", not production experience. Then show depth.</li>
            </ol>
          </Card>
        </div>
      </div>
    </div>
  )
}

export const GuideIcon = BookOpen
