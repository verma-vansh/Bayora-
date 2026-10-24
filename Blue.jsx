import { useCallback, useEffect, useState } from 'react'
import { api } from './api.js'
import { Badge, Card, Results, Summary } from './ui.jsx'

const TABS = ['Overview', 'Alerts', 'Audit log', 'Policies', 'Campaigns']

function useLoad(path, every) {
  const [data, setData] = useState(null)
  const [err, setErr] = useState('')
  const load = useCallback(() => api(path).then(d => { setData(d); setErr('') }).catch(e => setErr(e.message)), [path])
  useEffect(() => { load(); if (!every) return; const t = setInterval(load, every); return () => clearInterval(t) }, [load, every])
  return [data, err, load]
}

const EventTable = ({ rows }) => (
  <table>
    <thead><tr><th>#</th><th>Time</th><th>Actor</th><th>Event</th><th>Sev</th><th>Details</th><th>Hash</th></tr></thead>
    <tbody>{rows.map(e => (
      <tr key={e.seq}><td>{e.seq}</td><td className="small">{e.ts.replace('T', ' ').slice(0, 19)}</td><td>{e.actor} <span className="muted small">({e.role})</span></td>
        <td>{e.event_type}</td><td><Badge>{e.severity}</Badge></td>
        <td className="small det">{Object.entries(e.details).map(([k, v]) => `${k}=${Array.isArray(v) ? v.join(',') : v}`).join('  ')}</td>
        <td className="mono small">{e.hash.slice(0, 10)}</td></tr>
    ))}</tbody>
  </table>
)

function Overview() {
  const [stats, err] = useLoad('/blue/stats', 5000)
  const [ver, setVer] = useState(null)
  const verify = async () => setVer(await api('/blue/audit/verify'))
  useEffect(() => { verify().catch(() => {}) }, [])
  if (err) return <div className="error">{err}</div>
  if (!stats) return <p className="muted">Loading…</p>
  const a = stats.alerts_by_severity
  return (
    <>
      <div className="cards">
        <Card title="Audit events" value={stats.total} />
        <Card title="Critical alerts" value={a.critical || 0} kind={a.critical ? 'bad' : 'good'} />
        <Card title="High alerts" value={a.high || 0} kind={a.high ? 'bad' : 'good'} />
        <Card title="Blocked requests" value={stats.by_type['llm.blocked'] || 0} />
        <Card title="Secret leaks caught" value={stats.by_type['llm.leak_detected'] || 0} />
        <Card title="Denied boundary crossings" value={stats.by_type['access.denied'] || 0} />
      </div>
      <section>
        <h2>Audit chain integrity</h2>
        <div className="row">
          <button onClick={verify}>Verify now</button>
          {ver && (ver.valid
            ? <span><Badge kind="resisted">VALID</Badge> {ver.events} events · head <span className="mono">{ver.head_hash.slice(0, 16)}…</span></span>
            : <span><Badge kind="succeeded">TAMPERING DETECTED</Badge> first bad event #{ver.first_invalid_seq} ({ver.reason})</span>)}
        </div>
      </section>
      {stats.last_campaign && <section><h2>Latest red-team campaign</h2><p className="muted">by {stats.last_campaign.created_by} at {stats.last_campaign.created_at.slice(0, 19)}</p><Summary s={stats.last_campaign.summary} /></section>}
    </>
  )
}

function Alerts() {
  const [rows, err] = useLoad('/blue/alerts?limit=200', 5000)
  if (err) return <div className="error">{err}</div>
  return rows ? (rows.length ? <EventTable rows={rows} /> : <p className="muted">No alerts yet.</p>) : <p className="muted">Loading…</p>
}

function Audit() {
  const [prefix, setPrefix] = useState('')
  const [rows, err] = useLoad(`/blue/audit?limit=200${prefix ? `&event_prefix=${encodeURIComponent(prefix)}` : ''}`, 5000)
  return (
    <>
      <div className="row"><select value={prefix} onChange={e => setPrefix(e.target.value)}>
        <option value="">All events</option>{['llm.', 'alert.', 'auth.', 'access.', 'policy.', 'campaign.'].map(p => <option key={p} value={p}>{p}*</option>)}
      </select></div>
      {err && <div className="error">{err}</div>}
      {rows && <EventTable rows={rows} />}
    </>
  )
}

function Policies() {
  const [pol, err, reload] = useLoad('/blue/policies')
  const [rules] = useLoad('/blue/rules')
  const [f, setF] = useState({ name: '', kind: 'keyword', pattern: '', action: 'block', severity: 'high' })
  const [msg, setMsg] = useState('')
  const add = async () => { try { await api('/blue/policies', { method: 'POST', body: f }); setF({ ...f, name: '', pattern: '' }); setMsg(''); reload() } catch (e) { setMsg(e.message) } }
  return (
    <>
      <section>
        <h2>Custom gateway policies</h2>
        <p className="muted">Applied to every prompt immediately. Red team can never read these.</p>
        <div className="row wrap">
          <input placeholder="Name" value={f.name} onChange={e => setF({ ...f, name: e.target.value })} />
          <select value={f.kind} onChange={e => setF({ ...f, kind: e.target.value })}><option>keyword</option><option>regex</option></select>
          <input placeholder="Pattern" value={f.pattern} onChange={e => setF({ ...f, pattern: e.target.value })} />
          <select value={f.action} onChange={e => setF({ ...f, action: e.target.value })}><option>block</option><option>flag</option></select>
          <select value={f.severity} onChange={e => setF({ ...f, severity: e.target.value })}>{['low', 'medium', 'high', 'critical'].map(x => <option key={x}>{x}</option>)}</select>
          <button disabled={!f.name || !f.pattern} onClick={add}>Add policy</button>
        </div>
        {(msg || err) && <div className="error">{msg || err}</div>}
        {pol && <table><thead><tr><th>ID</th><th>Name</th><th>Type</th><th>Pattern</th><th>Action</th><th>Severity</th><th /></tr></thead>
          <tbody>{pol.map(p => <tr key={p.id}><td>CUS-{p.id}</td><td>{p.name}</td><td>{p.kind}</td><td className="mono">{p.pattern}</td><td>{p.action}</td><td><Badge>{p.severity}</Badge></td>
            <td><button className="ghost" onClick={async () => { await api(`/blue/policies/${p.id}`, { method: 'DELETE' }); reload() }}>Delete</button></td></tr>)}</tbody></table>}
      </section>
      <section>
        <h2>Built-in rules</h2>
        {rules && <table><thead><tr><th>ID</th><th>Category</th><th>Description</th><th>Action</th><th>Severity</th></tr></thead>
          <tbody>{rules.map(r => <tr key={r.id}><td>{r.id}</td><td>{r.category}</td><td>{r.description}</td><td>{r.action}</td><td><Badge>{r.severity}</Badge></td></tr>)}</tbody></table>}
      </section>
    </>
  )
}

function Campaigns() {
  const [list, err] = useLoad('/blue/campaigns', 10000)
  const [sel, setSel] = useState(null)
  return (
    <>
      {err && <div className="error">{err}</div>}
      {list && <table><thead><tr><th>When</th><th>By</th><th>Mode</th><th>Success</th><th>Risk</th><th>FP</th><th /></tr></thead>
        <tbody>{list.map(c => <tr key={c.id}><td className="small">{c.created_at.slice(0, 19).replace('T', ' ')}</td><td>{c.created_by}</td><td>{c.mode}</td>
          <td>{c.summary.attack_success_rate}%</td><td>{c.summary.risk_score}</td><td>{c.summary.false_positive_rate}%</td>
          <td><button className="ghost" onClick={async () => setSel(await api(`/blue/campaigns/${c.id}`))}>Details</button></td></tr>)}</tbody></table>}
      {sel && <section><h2>Campaign {sel.id.slice(0, 8)}</h2><Summary s={sel.summary} /><Results rows={sel.results} showRule /></section>}
    </>
  )
}

export default function Blue() {
  const [tab, setTab] = useState('Overview')
  const View = { Overview, Alerts, 'Audit log': Audit, Policies, Campaigns }[tab]
  return (
    <>
      <nav className="tabs">{TABS.map(t => <button key={t} className={t === tab ? 'on' : ''} onClick={() => setTab(t)}>{t}</button>)}</nav>
      <View />
    </>
  )
}
