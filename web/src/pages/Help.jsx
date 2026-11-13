import { useState } from 'react'
import { LifeBuoy, Copy, Check, ChevronDown, Bot, ArrowUpRight, CheckCircle2, GraduationCap, Info } from 'lucide-react'
import { PageHeader, Card, Badge, Button, toast } from '../ui.jsx'
import { LABS, mentorPrompt, MASTER_PROMPT, HOW_TO, SOURCE_NOTE } from '../help.js'
import { PROJECTS } from '../guide.js'

function CopyBtn({ text, label = 'Copy', variant = 'ghost' }) {
  const [done, setDone] = useState(false)
  return (
    <Button size="sm" variant={variant} onClick={async () => {
      try { await navigator.clipboard.writeText(text); setDone(true); setTimeout(() => setDone(false), 1500) } catch { toast('Copy failed', 'err') }
    }}>{done ? <Check className="size-3.5" /> : <Copy className="size-3.5" />}{done ? 'Copied' : label}</Button>
  )
}

function Lab({ lab, open, onToggle }) {
  const prompt = mentorPrompt(lab)
  const description = `${lab.title}\n\n${lab.summary}\n\nSteps:\n${lab.steps.map(([s], i) => `${i + 1}. ${s}`).join('\n')}\n\nLearning outcomes:\n${lab.outcomes.map((o) => `- ${o}`).join('\n')}`
  const skills = PROJECTS.find((p) => p.n === lab.n)?.skills || []
  return (
    <section id={`lab-${lab.n}`} className="panel scroll-mt-20 overflow-hidden animate-fade-up">
      <button type="button" onClick={onToggle} aria-expanded={open} className="flex w-full items-start gap-4 px-5 py-4 text-start hover:bg-white/[0.02]">
        <span className="inline-flex size-10 shrink-0 items-center justify-center rounded-xl bg-gradient-to-br from-violet-500 to-indigo-600 font-display font-bold text-white">{lab.n}</span>
        <span className="min-w-0 flex-1">
          <span className="block font-semibold text-zinc-100">{lab.title}</span>
          <span className="mt-0.5 block text-sm text-zinc-400">{lab.summary}</span>
          <span className="mt-2 flex flex-wrap gap-1.5">{skills.map((s) => <Badge key={s} tone="violet">{s}</Badge>)}</span>
        </span>
        <span className="hidden shrink-0 items-center gap-1.5 text-xs text-emerald-300 sm:flex"><CheckCircle2 className="size-4" />{lab.steps.length}/{lab.steps.length} in app</span>
        <ChevronDown className={`mt-1 size-4 shrink-0 text-zinc-500 transition ${open ? 'rotate-180' : ''}`} />
      </button>
      {open && (
        <div className="grid gap-6 border-t border-white/[0.06] p-5 lg:grid-cols-5 animate-fade-in">
          <div className="lg:col-span-3">
            <div className="eyebrow mb-2">Lab steps and where to do each one here</div>
            <ol className="space-y-2">
              {lab.steps.map(([step, how, id, where], i) => (
                <li key={i} className="flex gap-3 rounded-xl border border-white/[0.06] bg-white/[0.02] p-3">
                  <span className="inline-flex size-6 shrink-0 items-center justify-center rounded-full bg-emerald-500/15 text-xs font-bold text-emerald-300">{i + 1}</span>
                  <div className="min-w-0 flex-1">
                    <div className="text-sm font-medium text-zinc-100">{step}</div>
                    <div className="mt-0.5 text-xs leading-relaxed text-zinc-400">{how}</div>
                  </div>
                  <a href={`#${id}`} className="inline-flex shrink-0 items-center gap-1 self-start rounded-lg px-2 py-1 text-[11px] font-semibold text-violet-300 ring-1 ring-inset ring-violet-500/30 hover:bg-violet-500/10" title={`Open ${where}`}>
                    <span className="hidden max-w-40 truncate sm:inline">{where}</span><ArrowUpRight className="size-3" />
                  </a>
                </li>
              ))}
            </ol>
            <div className="mt-4 eyebrow mb-2">What you'll be able to say you can do</div>
            <ul className="grid gap-1.5 sm:grid-cols-2">{lab.outcomes.map((o) => <li key={o} className="flex gap-2 text-sm text-zinc-300"><CheckCircle2 className="mt-0.5 size-4 shrink-0 text-emerald-400" />{o}</li>)}</ul>
          </div>
          <div className="space-y-4 lg:col-span-2">
            <div className="rounded-xl border border-violet-500/25 bg-violet-500/[0.05] p-4">
              <div className="mb-1 flex items-center gap-2 text-sm font-semibold text-violet-100"><Bot className="size-4" /> Do it on a real platform with an AI mentor</div>
              <p className="mb-3 text-xs leading-relaxed text-zinc-400">Copy this, paste it into Claude, ChatGPT or Copilot, and you get a full walkthrough: setup, tools, configuration, policies, test cases, logs to check and how to document it. Suggested platform: {lab.platforms}.</p>
              <pre className="max-h-60 overflow-auto whitespace-pre-wrap rounded-lg bg-zinc-950/80 p-3 font-mono text-[11px] leading-relaxed text-zinc-300">{prompt}</pre>
              <div className="mt-3 flex flex-wrap gap-2">
                <CopyBtn text={prompt} label="Copy AI walkthrough prompt" variant="primary" />
                <CopyBtn text={description} label="Copy project description" />
              </div>
            </div>
            <a href={`#guide`} onClick={() => setTimeout(() => document.getElementById(`p-${lab.n}`)?.scrollIntoView({ behavior: 'smooth' }), 300)}
              className="flex items-center justify-between rounded-xl border border-white/[0.07] p-3 text-sm text-zinc-300 hover:border-white/15">
              <span><GraduationCap className="me-2 inline size-4 text-amber-300" />Interview story, resume bullet and screenshots</span><ArrowUpRight className="size-4 text-zinc-500" />
            </a>
          </div>
        </div>
      )}
    </section>
  )
}

export default function Help() {
  const [open, setOpen] = useState(1)
  return (
    <div className="space-y-6">
      <PageHeader icon={LifeBuoy} eyebrow="Help center · lab guides · AI mentor prompts" title="Help & lab guides"
        desc="Every one of the 10 standard IAM analyst projects, broken into its lab steps, with a link to where each step is done in this app. Each lab also has a ready-made prompt: paste it into any AI chatbot and it will coach you through the same lab on Entra ID, Okta, AWS, Azure or Keycloak, including test cases, logs to check and how to write it up for your resume." />

      <div className="grid gap-6 lg:grid-cols-5">
        <Card className="lg:col-span-3" title="How to use this app">
          <dl className="grid gap-3 sm:grid-cols-2">
            {HOW_TO.map(([k, v]) => (
              <div key={k} className="rounded-xl border border-white/[0.06] bg-white/[0.02] p-3">
                <dt className="text-sm font-semibold text-zinc-100">{k}</dt>
                <dd className="mt-1 text-xs leading-relaxed text-zinc-400">{v}</dd>
              </div>
            ))}
          </dl>
        </Card>
        <Card className="lg:col-span-2" title="Use AI as your IAM mentor" subtitle="Start a chat with this, then paste any lab below">
          <pre className="max-h-48 overflow-auto whitespace-pre-wrap rounded-lg bg-zinc-950/80 p-3 font-mono text-[11px] leading-relaxed text-zinc-300">{MASTER_PROMPT}</pre>
          <div className="mt-3"><CopyBtn text={MASTER_PROMPT} label="Copy mentor prompt" variant="primary" /></div>
          <p className="mt-3 flex gap-2 text-[11px] leading-relaxed text-zinc-500"><Info className="mt-0.5 size-3.5 shrink-0" />Use a free tenant or trial for real-platform labs and never paste real passwords, keys or company data into a chatbot.</p>
        </Card>
      </div>

      <div className="flex flex-wrap gap-2">
        {LABS.map((l) => (
          <button key={l.n} type="button" onClick={() => { setOpen(l.n); setTimeout(() => document.getElementById(`lab-${l.n}`)?.scrollIntoView({ behavior: 'smooth' }), 50) }}
            className={`rounded-full px-3 py-1 text-xs font-semibold ring-1 ring-inset transition ${open === l.n ? 'bg-violet-500/20 text-violet-100 ring-violet-500/40' : 'text-zinc-400 ring-white/10 hover:text-zinc-200'}`}>
            {l.n}. {l.title.split(' (')[0]}
          </button>
        ))}
      </div>

      <div className="space-y-3">
        {LABS.map((l) => <Lab key={l.n} lab={l} open={open === l.n} onToggle={() => setOpen(open === l.n ? 0 : l.n)} />)}
      </div>

      <p className="text-center text-[11px] text-zinc-500">{SOURCE_NOTE}</p>
    </div>
  )
}
