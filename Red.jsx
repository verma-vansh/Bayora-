import { useEffect, useState } from 'react'
import { api } from './api.js'
import { Badge, Results, Summary } from './ui.jsx'

export default function Red() {
  const [prompt, setPrompt] = useState('')
  const [mode, setMode] = useState('enforce')
  const [out, setOut] = useState(null)
  const [attacks, setAttacks] = useState([])
  const [camp, setCamp] = useState(null)
  const [busy, setBusy] = useState('')
  const [err, setErr] = useState('')

  useEffect(() => { api('/red/attacks').then(setAttacks).catch(e => setErr(e.message)) }, [])
  const run = async (label, fn) => { setBusy(label); setErr(''); try { await fn() } catch (e) { setErr(e.message) } finally { setBusy('') } }

  return (
    <>
      <section>
        <h2>Probe the target LLM</h2>
        <p className="muted">Requests pass through the Secure Gateway. Secrets in model output are always redacted before you see them.</p>
        <textarea rows={4} value={prompt} onChange={e => setPrompt(e.target.value)} placeholder="Enter an adversarial prompt…" />
        <div className="row">
          <select value={mode} onChange={e => setMode(e.target.value)}>
            <option value="enforce">Gateway: enforce</option><option value="monitor">Gateway: monitor only (test the raw model)</option>
          </select>
          <button disabled={!prompt || busy} onClick={() => run('probe', async () => setOut(await api('/red/probe', { method: 'POST', body: { prompt, mode } })))}>
            {busy === 'probe' ? 'Sending…' : 'Send'}
          </button>
        </div>
        {out && (
          <div className="resp">
            <div>{out.blocked && <Badge kind="blocked">blocked</Badge>} {out.leaked && <Badge kind="succeeded">secret leaked (redacted)</Badge>} {out.unsafe && <Badge kind="succeeded">unsafe completion</Badge>} <span className="muted small">{out.latency_ms} ms</span></div>
            <pre>{out.response}</pre>
          </div>
        )}
      </section>

      <section>
        <h2>Automated campaign</h2>
        <div className="row">
          <button disabled={busy} onClick={() => run('camp', async () => setCamp(await api('/red/campaigns', { method: 'POST', body: { mode } })))}>
            {busy === 'camp' ? 'Running…' : `Run full attack suite (${attacks.length} prompts, ${mode})`}
          </button>
        </div>
        {camp && <><Summary s={camp.summary} /><Results rows={camp.results} /></>}
      </section>

      <section>
        <h2>Attack library</h2>
        <table>
          <thead><tr><th>ID</th><th>Name</th><th>Category</th><th>Severity</th><th /></tr></thead>
          <tbody>{attacks.map(a => (
            <tr key={a.id}><td>{a.id}</td><td>{a.name}</td><td>{a.category}</td><td><Badge>{a.severity}</Badge></td>
              <td><button className="ghost" onClick={() => setPrompt(a.prompt)}>Load</button></td></tr>
          ))}</tbody>
        </table>
      </section>
      {err && <div className="error">{err}</div>}
    </>
  )
}
