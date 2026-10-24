import { useState } from 'react'
import { api, session } from './api.js'
import Red from './Red.jsx'
import Blue from './Blue.jsx'

function Login({ onDone }) {
  const [u, setU] = useState('')
  const [p, setP] = useState('')
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)
  const submit = async (e) => {
    e.preventDefault(); setBusy(true); setErr('')
    try { const s = await api('/auth/login', { method: 'POST', body: { username: u, password: p } }); s.username = u; session.set(s); onDone(s) }
    catch (x) { setErr(x.message) } finally { setBusy(false) }
  }
  return (
    <div className="login">
      <h1>BAYORA</h1>
      <p className="muted">Attack the AI without exposing the attack.</p>
      <form onSubmit={submit}>
        <input placeholder="Username" value={u} onChange={e => setU(e.target.value)} autoComplete="username" />
        <input placeholder="Password" type="password" value={p} onChange={e => setP(e.target.value)} autoComplete="current-password" />
        <button disabled={busy || !u || !p}>{busy ? 'Signing in…' : 'Sign in'}</button>
        {err && <div className="error">{err}</div>}
      </form>
    </div>
  )
}

export default function App() {
  const [s, setS] = useState(session.get())
  if (!s) return <Login onDone={setS} />
  const logout = () => { session.clear(); setS(null) }
  return (
    <div className={`shell ${s.role}`}>
      <header>
        <b>BAYORA</b>
        <span className={`zone ${s.role}`}>{s.role.toUpperCase()} ZONE</span>
        <span className="spacer" />
        <span className="muted">{s.username}</span>
        <button className="ghost" onClick={logout}>Sign out</button>
      </header>
      <main>
        {s.role === 'blue' ? <Blue /> : s.role === 'red' ? <Red /> : <AdminBoth />}
      </main>
    </div>
  )
}

function AdminBoth() {
  const [tab, setTab] = useState('blue')
  return (
    <>
      <nav className="tabs">
        <button className={tab === 'blue' ? 'on' : ''} onClick={() => setTab('blue')}>Blue console</button>
        <button className={tab === 'red' ? 'on' : ''} onClick={() => setTab('red')}>Red console</button>
      </nav>
      {tab === 'blue' ? <Blue /> : <Red />}
    </>
  )
}
