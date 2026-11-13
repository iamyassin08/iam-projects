import { useEffect, useState } from 'react'
import { Fingerprint, LogIn, LogOut, Play, CheckCircle2, Server, Globe, ExternalLink, KeyRound, Boxes } from 'lucide-react'
import { api } from '../api.js'
import { useLoad, PageHeader, Card, Badge, Button, ErrorBox, Loading, Seg, toast, Avatar, Tooltip, usePreline } from '../ui.jsx'
import { JWTView, ClaimsTable, Sequence, CodeBlock } from '../components.jsx'
import realm from '../../../keycloak/realm-assafwah.json?raw'

export const OIDC_STEPS = [
  { from: 0, to: 1, label: 'GET /auth/login', note: 'The user clicks Sign in. The app (relying party) has no session yet.' },
  { from: 1, to: 0, label: '302 → /authorize  (state, nonce, PKCE challenge)', note: 'The app generates a random state (CSRF), nonce (replay) and a PKCE code_verifier, stores them in a signed, HttpOnly cookie, and sends only the SHA-256 code_challenge to the IdP.' },
  { from: 0, to: 2, label: 'GET /idp/authorize?client_id&redirect_uri…', note: 'The IdP checks the client_id, that redirect_uri is registered (stops token theft by open redirect), response_type=code, scope=openid and PKCE S256.' },
  { from: 2, to: 2, label: 'Password → Conditional Access → MFA', note: 'Hosted sign-in page: verify the password (PBKDF2 hash, smart lockout), evaluate Conditional Access (location, device, client app, risk), then require TOTP if a policy says so. Every attempt goes to the sign-in log.' },
  { from: 2, to: 0, label: '302 → redirect_uri?code&state', note: 'A one-time authorization code valid for 60 seconds. The code alone is useless without the client secret and the PKCE verifier.' },
  { from: 0, to: 1, label: 'GET /auth/callback?code&state', note: 'The app compares state with the value in its signed cookie. A mismatch means a forged callback, so the sign-in is rejected.' },
  { from: 1, to: 2, label: 'POST /token  code + code_verifier + secret', note: 'Back-channel call: the browser never sees the tokens being minted. The IdP checks the client secret, that the code matches this client and redirect_uri, and that SHA-256(code_verifier) equals the earlier challenge. Codes are single use.' },
  { from: 2, to: 1, label: 'id_token + access_token (RS256 JWTs)', note: 'Signed with the IdP private key. The id_token says who signed in and how (amr, acr); the access_token is for calling APIs.' },
  { from: 1, to: 1, label: 'Verify signature (JWKS), iss, aud, exp, nonce', note: 'The app fetches the public key from /jwks and checks the RS256 signature, then the issuer, audience, expiry and that nonce matches its cookie. Only then is a session created.' },
  { from: 1, to: 0, label: 'Session cookie: you are signed in', note: 'HttpOnly, SameSite=Lax, HMAC-signed. From here every audit-log entry is attributed to the signed-in user, not a shared admin account.' },
]

const APPS = [
  { name: 'IAM Projects console', proto: 'OIDC', idp: 'Assafwah IdP (built-in)', status: 'live', how: 'Auth code + PKCE, confidential client, RS256 ID token verified against JWKS', roles: 'groups claim → approver / iam-admins' },
  { name: 'IAM Projects console', proto: 'OIDC', idp: 'Keycloak · keycloak.assafwahinc.com', status: 'live', how: 'Realm assafwah, client iam-projects: PKCE S256, TOTP required action, brute-force lockout', roles: 'groups + realm_access.roles → iam-admin / approver' },
  { name: 'Microsoft 365', proto: 'SAML 2.0', idp: 'Entra ID', status: 'simulated', how: 'SP-initiated SAML, signed assertions, NameID = UPN', roles: 'Group claims → licences' },
  { name: 'AWS IAM Identity Center', proto: 'SAML 2.0 + SCIM', idp: 'Entra ID', status: 'simulated', how: 'SAML for sign-in, SCIM for users and groups', roles: 'Group → permission set' },
  { name: 'GitHub Enterprise', proto: 'SAML 2.0 + SCIM', idp: 'Entra ID', status: 'simulated', how: 'SAML SSO enforced on the org', roles: 'Team sync from groups' },
]

const SAML = `<saml2:Assertion ID="_a75adf55" IssueInstant="2026-11-13T15:02:11Z" Version="2.0">
  <saml2:Issuer>https://sts.windows.net/{tenant-id}/</saml2:Issuer>
  <ds:Signature>… RSA-SHA256 over the assertion …</ds:Signature>
  <saml2:Subject>
    <saml2:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">yusuf.ali@demo.local</saml2:NameID>
    <saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
      <saml2:SubjectConfirmationData Recipient="https://signin.aws.amazon.com/saml" NotOnOrAfter="2026-11-13T15:07:11Z"/>
    </saml2:SubjectConfirmation>
  </saml2:Subject>
  <saml2:Conditions NotBefore="2026-11-13T14:57:11Z" NotOnOrAfter="2026-11-13T16:02:11Z">
    <saml2:AudienceRestriction><saml2:Audience>urn:amazon:webservices</saml2:Audience></saml2:AudienceRestriction>
  </saml2:Conditions>
  <saml2:AuthnStatement AuthnInstant="2026-11-13T15:02:10Z">
    <saml2:AuthnContext><saml2:AuthnContextClassRef>…:MultiFactor</saml2:AuthnContextClassRef></saml2:AuthnContext>
  </saml2:AuthnStatement>
  <saml2:AttributeStatement>
    <saml2:Attribute Name="https://aws.amazon.com/SAML/Attributes/Role">
      <saml2:AttributeValue>arn:aws:iam::111122223333:role/IAMEngineer,arn:aws:iam::111122223333:saml-provider/EntraID</saml2:AttributeValue>
    </saml2:Attribute>
  </saml2:AttributeStatement>
</saml2:Assertion>`

export default function SSO() {
  const [data, reload, error] = useLoad({ me: api.me, disc: api.discovery, jwks: api.jwks })
  const [step, setStep] = useState(-1)
  const [playing, setPlaying] = useState(false)
  const [tok, setTok] = useState('id')
  const [proto, setProto] = useState('oidc')
  usePreline([data])

  const err = new URLSearchParams(window.location.hash.split('?')[1] || '').get('error')
  useEffect(() => { if (err) toast(err, 'err') }, [err])
  useEffect(() => {
    if (!playing) return
    if (step >= OIDC_STEPS.length - 1) { setPlaying(false); return }
    const t = setTimeout(() => setStep((s) => s + 1), 1500)
    return () => clearTimeout(t)
  }, [playing, step])

  async function logout() { await api.logout(); await reload(); toast('Signed out') }

  if (!data) return <><ErrorBox error={error} /><Loading /></>
  const { me, disc, jwks } = data
  const kc = me.providers.find((p) => p.id === 'keycloak')
  const t = tok === 'id' ? me.tokens?.idToken : me.tokens?.accessToken

  return (
    <div className="space-y-6">
      <PageHeader icon={Fingerprint} eyebrow="Project 3 & 9 · SSO, federation, OpenID Connect, SAML, Keycloak" title="Single sign-on & federation"
        desc="This console is a real OpenID Connect relying party, and it ships its own OpenID provider. Sign in below and the full authorization-code + PKCE flow runs end to end: hosted sign-in, Conditional Access, MFA, a signed ID token verified against the JWKS, then a session that attributes every audit entry to you. Point OIDC_ISSUER at a Keycloak realm and the same code signs you in through Keycloak." />
      <ErrorBox error={error} />

      <div className="grid gap-6 lg:grid-cols-5">
        <Card className="lg:col-span-2" title="Your session" subtitle={me.authenticated ? `Signed in via ${me.user.idp === 'keycloak' ? 'Keycloak' : 'the built-in IdP'}` : 'Not signed in: actions are attributed to the demo admin'}>
          {me.authenticated ? (
            <div className="space-y-4">
              <div className="flex items-center gap-3">
                <Avatar name={me.user.n} size="size-11" />
                <div><div className="font-semibold text-white">{me.user.n}</div><div className="text-xs text-zinc-500">{me.user.u} · {me.user.e}</div></div>
              </div>
              <div className="flex flex-wrap gap-1.5">{me.user.g.map((g) => <Badge key={g} tone="violet">{g}</Badge>)}</div>
              <div className="flex flex-wrap gap-1.5">{me.user.amr.map((a) => <Badge key={a} tone={a === 'mfa' || a === 'otp' ? 'ok' : 'neutral'}>amr: {a}</Badge>)}</div>
              <ul className="space-y-1 text-xs text-zinc-400">
                {['RS256 signature verified against /jwks', 'iss and aud match this client', 'nonce matches the login cookie', 'state checked (CSRF)', 'PKCE verifier accepted by /token'].map((x) => (
                  <li key={x} className="flex items-center gap-2"><CheckCircle2 className="size-3.5 text-emerald-400" />{x}</li>
                ))}
              </ul>
              <Button variant="ghost" onClick={logout}><LogOut className="size-4" /> Sign out</Button>
            </div>
          ) : (
            <div className="space-y-3">
              <a href="/auth/login" className="block"><Button className="w-full"><LogIn className="size-4" /> Sign in with Assafwah IdP</Button></a>
              {kc.configured ? (
                <a href="/auth/login?idp=keycloak" className="block"><Button variant="ghost" className="w-full"><KeyRound className="size-4" /> Sign in with Keycloak</Button></a>
              ) : (
                <Tooltip tip="Set OIDC_ISSUER, OIDC_CLIENT_ID and OIDC_CLIENT_SECRET to a Keycloak realm (see docs/KEYCLOAK.md)" className="w-full">
                  <Button variant="ghost" className="w-full" disabled><KeyRound className="size-4" /> Sign in with Keycloak (not configured)</Button>
                </Tooltip>
              )}
              <p className="text-xs leading-relaxed text-zinc-500">Try <span className="code">yusuf.ali</span> (admin: MFA always), <span className="code">sofia.alvarez</span> (no MFA yet: you'll enrol a TOTP app), or sign in "from Moscow" to see a Conditional Access block.</p>
            </div>
          )}
        </Card>

        <Card className="lg:col-span-3" title="Token inspector" subtitle={me.authenticated ? `${me.tokens?.provider} · ${me.tokens?.issuer}` : 'Sign in to see the real tokens issued to you'}
          actions={me.authenticated && <Seg value={tok} onChange={setTok} options={[{ value: 'id', label: 'ID token' }, { value: 'at', label: 'Access token' }]} />}>
          {me.authenticated && t ? (
            <div className="space-y-3">
              <JWTView raw={t.raw} />
              <div className="flex flex-wrap gap-2 text-[11px]"><Badge tone="bad">header</Badge><Badge tone="violet">payload (claims)</Badge><Badge tone="info">RS256 signature</Badge><span className="text-zinc-500">kid {t.header?.kid}</span></div>
              <ClaimsTable claims={t.claims} />
            </div>
          ) : (
            <div className="grid place-items-center gap-2 py-10 text-center text-sm text-zinc-500"><Fingerprint className="size-8 text-zinc-600" />Header · payload · signature, every claim explained.</div>
          )}
        </Card>
      </div>

      <Card title="Authorization code flow with PKCE" subtitle="Click a step, or play it. This is exactly what happens when you press Sign in."
        actions={<Button size="sm" variant="ghost" onClick={() => { setStep(0); setPlaying(true) }}><Play className="size-3.5" /> Play</Button>}>
        <div className="grid gap-6 lg:grid-cols-5">
          <div className="lg:col-span-3"><Sequence lanes={['Browser', 'IAM Projects (RP)', 'Assafwah IdP']} steps={OIDC_STEPS} active={step} onStep={(i) => { setPlaying(false); setStep(i) }} /></div>
          <div className="lg:col-span-2">
            {step >= 0 ? (
              <div key={step} className="rounded-xl border border-violet-500/20 bg-violet-500/[0.05] p-4 animate-fade-in">
                <div className="eyebrow mb-1">Step {step + 1} of {OIDC_STEPS.length}</div>
                <div className="font-mono text-sm text-violet-200">{OIDC_STEPS[step].label}</div>
                <p className="mt-2 text-sm leading-relaxed text-zinc-300">{OIDC_STEPS[step].note}</p>
              </div>
            ) : <p className="text-sm text-zinc-500">Pick a step to see what is checked and why.</p>}
            <div className="mt-4 rounded-xl border border-white/[0.07] p-4 text-xs leading-relaxed text-zinc-400">
              <div className="mb-1 font-semibold text-zinc-200">Why PKCE?</div>
              If an attacker steals the authorization code from a redirect, they still can't redeem it: the token endpoint wants the original
              <span className="code mx-1">code_verifier</span>, which never left the app. OAuth 2.1 requires it for every client.
            </div>
          </div>
        </div>
      </Card>

      <Card title="Connected applications (federation trusts)" subtitle="Which app trusts which IdP, over which protocol" pad={false}>
        <div className="overflow-x-auto">
          <table className="min-w-full">
            <thead><tr><th className="th">Application</th><th className="th">Protocol</th><th className="th">Identity provider</th><th className="th">How it's wired</th><th className="th">Authorization</th><th className="th">Status</th></tr></thead>
            <tbody>
              {APPS.map((a) => (
                <tr key={a.name + a.idp} className="row">
                  <td className="td font-medium text-zinc-100">{a.name}</td>
                  <td className="td"><Badge tone={a.proto.startsWith('OIDC') ? 'violet' : 'info'}>{a.proto}</Badge></td>
                  <td className="td text-zinc-300">{a.idp}</td>
                  <td className="td text-xs text-zinc-400">{a.how}</td>
                  <td className="td text-xs text-zinc-400">{a.roles}</td>
                  <td className="td"><Badge tone={a.status === 'live' ? 'ok' : a.status === 'ready' ? 'warn' : 'neutral'} dot>{a.status}</Badge></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>

      <div className="grid gap-6 lg:grid-cols-2">
        <Card title="Protocol reference" subtitle="What each protocol actually sends" actions={<Seg value={proto} onChange={setProto} options={[{ value: 'oidc', label: 'OIDC discovery' }, { value: 'jwks', label: 'JWKS' }, { value: 'saml', label: 'SAML assertion' }]} />}>
          {proto === 'oidc' && <CodeBlock lang="GET /idp/.well-known/openid-configuration">{JSON.stringify(disc, null, 2)}</CodeBlock>}
          {proto === 'jwks' && <CodeBlock lang="GET /idp/jwks">{JSON.stringify(jwks, null, 2)}</CodeBlock>}
          {proto === 'saml' && <>
            <CodeBlock lang="SAML 2.0 assertion (illustrative, Entra ID → AWS)">{SAML}</CodeBlock>
            <p className="mt-2 text-xs leading-relaxed text-zinc-500">SAML: XML, signed assertion posted by the browser, trust via exchanged metadata and certificates. OIDC: JSON/JWT on top of OAuth 2.0, keys published at a JWKS URL. Both establish the same thing: the app trusts the IdP to say who the user is.</p>
          </>}
        </Card>

        <Card title="Keycloak (open-source IdP)" subtitle="Realm export in keycloak/realm-assafwah.json" actions={<a href="https://github.com/iamyassin08/iam-projects/blob/main/docs/KEYCLOAK.md" target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 text-xs font-semibold text-violet-300">Setup guide <ExternalLink className="size-3" /></a>}>
          <div className="mb-3 grid grid-cols-2 gap-2 text-xs">
            {[[Boxes, 'Realm', 'assafwah'], [Globe, 'Client', 'iam-projects (PKCE S256)'], [KeyRound, 'MFA', 'TOTP required action'], [Server, 'Lockout', '5 failures, 15 min max wait'], [CheckCircle2, 'Roles', 'iam-admin, approver (from groups)'], [Fingerprint, 'Events', 'login + admin events, 30 days']].map(([I, k, v]) => (
              <div key={k} className="flex items-start gap-2 rounded-lg border border-white/[0.06] bg-white/[0.02] p-2"><I className="mt-0.5 size-3.5 text-violet-300" /><div><div className="text-zinc-500">{k}</div><div className="text-zinc-200">{v}</div></div></div>
            ))}
          </div>
          <CodeBlock lang="Coolify env for iam.assafwahinc.com" maxH="max-h-40">{`OIDC_ISSUER=https://keycloak.assafwahinc.com/realms/assafwah
OIDC_CLIENT_ID=iam-projects
OIDC_CLIENT_SECRET=<Clients → iam-projects → Credentials>`}</CodeBlock>
          <p className="mt-2 text-xs text-zinc-500">Keycloak demo users: <span className="code">yusuf.ali</span>, <span className="code">omar.farouk</span>, <span className="code">sofia.alvarez</span> · password <span className="code">Demo!2026-Keycloak</span> · TOTP enrolment on first sign-in.</p>
          <details className="mt-3">
            <summary className="cursor-pointer text-xs font-semibold text-zinc-400 hover:text-zinc-200">View realm-assafwah.json</summary>
            <CodeBlock lang="json" className="mt-2">{realm}</CodeBlock>
          </details>
          <Badge tone={kc.configured ? 'ok' : 'neutral'} dot className="mt-3">{kc.configured ? `Connected: ${kc.issuer}` : 'Not connected on this deployment'}</Badge>
        </Card>
      </div>
    </div>
  )
}
