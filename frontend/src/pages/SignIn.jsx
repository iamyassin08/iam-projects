import { useEffect, useState } from 'react'
import { ShieldCheck, Lock } from 'lucide-react'
import { api } from '../api.js'
import IdpFlow from './IdpFlow.jsx'

// Hosted sign-in page of the built-in IdP (the equivalent of Entra's or
// Keycloak's login screen). Reached via /idp/authorize → /#signin?txn=…
// The app's own #login page embeds the same flow without navigating here.

export default function SignIn() {
  const txn = new URLSearchParams(window.location.hash.split('?')[1] || '').get('txn')
  const [info, setInfo] = useState(null)
  const [err, setErr] = useState('')
  const [username, setUsername] = useState('yusuf.ali')

  useEffect(() => {
    if (!txn) { setErr('No sign-in in progress. Start from the application.'); return }
    api.txn(txn).then((i) => { setInfo(i); if (i.loginHint) setUsername(i.loginHint) }).catch((e) => setErr(e.message))
  }, [txn])

  return (
    <div className="flex min-h-screen items-center justify-center px-4 py-10">
      <div className="w-full max-w-md animate-scale-in">
        <div className="mb-6 flex items-center justify-center gap-2.5">
          <span className="inline-flex size-10 items-center justify-center rounded-xl bg-gradient-to-br from-violet-500 to-indigo-600 shadow-lg shadow-violet-900/40"><ShieldCheck className="size-5 text-white" /></span>
          <div>
            <div className="font-display text-base font-bold text-white">Assafwah IdP</div>
            <div className="text-[10px] uppercase tracking-[0.16em] text-zinc-500">OpenID Connect · demo tenant</div>
          </div>
        </div>

        <div className="panel overflow-hidden">
          <div className="border-b border-white/[0.06] px-6 py-4">
            <div className="text-xs text-zinc-500">Sign in to continue to</div>
            <div className="font-semibold text-zinc-100">{info?.client || '…'}</div>
            {info && <div className="mt-1 font-mono text-[10px] text-zinc-500">scope: {info.scope} · PKCE S256</div>}
          </div>

          <div className="p-6">
            {err && <div className="mb-4 flex items-start gap-2 rounded-lg border border-rose-500/30 bg-rose-500/10 px-3 py-2 text-sm text-rose-300"><Lock className="mt-0.5 size-4 shrink-0" />{err}</div>}
            {info && <IdpFlow txn={txn} username={username} setUsername={setUsername} />}
          </div>
        </div>
        <p className="mt-4 text-center text-xs"><a href="/#login" className="font-semibold text-violet-300 hover:text-violet-200">← Other sign-in options</a></p>
        <p className="mt-2 text-center text-[11px] text-zinc-500">Fictional users. Every attempt is written to the sign-in log on the Identity threat detection page.</p>
      </div>
    </div>
  )
}
