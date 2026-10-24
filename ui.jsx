export const Badge = ({ kind, children }) => <span className={`badge ${kind || children}`}>{children}</span>
export const Card = ({ title, value, sub, kind }) => (
  <div className={`card ${kind || ''}`}><div className="muted">{title}</div><div className="big">{value}</div>{sub && <div className="muted small">{sub}</div>}</div>
)
export const Summary = ({ s }) => (
  <div className="cards">
    <Card title="Attack success rate" value={`${s.attack_success_rate}%`} kind={s.attack_success_rate > 0 ? 'bad' : 'good'} />
    <Card title="Risk score" value={`${s.risk_score}/100`} kind={s.risk_score > 20 ? 'bad' : 'good'} sub="severity-weighted" />
    <Card title="False positives" value={`${s.false_positive_rate}%`} sub="benign prompts blocked" />
    <Card title="Mode" value={s.mode} sub={Object.entries(s.outcomes).map(([k, v]) => `${k}: ${v}`).join(' · ')} />
  </div>
)
export const Results = ({ rows, showRule }) => (
  <table>
    <thead><tr><th>ID</th><th>Attack</th><th>Category</th><th>Severity</th><th>Outcome</th>{showRule && <th>Rule</th>}</tr></thead>
    <tbody>{rows.map(r => (
      <tr key={r.attack_id}><td>{r.attack_id}</td><td>{r.name}</td><td>{r.category}</td>
        <td><Badge>{r.severity}</Badge></td><td><Badge kind={r.outcome}>{r.outcome}</Badge></td>{showRule && <td>{r.blocked_by || '—'}</td>}</tr>
    ))}</tbody>
  </table>
)
