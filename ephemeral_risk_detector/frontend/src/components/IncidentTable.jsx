import { useState } from 'react'

function SevBadge({ sev }) {
  return <span className={`sev sev-${sev}`}>{sev}</span>
}

function NarrativePanel({ incident }) {
  const mitre = Object.entries(incident.mitre_techniques || {})

  return (
    <div className="narrative-panel">
      <div className="narrative-hdr">
        🤖 AI-GENERATED ANALYST NARRATIVE
        <span className="opt-tag opt-a">Option A — Groq LLM / Template</span>
      </div>

      <div className="narrative-body">
        {incident.narrative || 'No narrative available.'}
      </div>

      {mitre.length > 0 && (
        <div className="mitre-chips">
          {mitre.map(([code, name]) => (
            <span key={code} className="mitre-chip">{code} — {name}</span>
          ))}
        </div>
      )}

      {incident.evidence?.length > 0 && (
        <div className="evidence-section">
          <div className="evidence-title">EVIDENCE EVENTS (first 5)</div>
          {incident.evidence.map((ev, i) => (
            <div key={i} className="evidence-row">
              <span>{ev.event_id}</span>
              &nbsp;·&nbsp;{ev.event_type}
              &nbsp;·&nbsp;{ev.timestamp?.slice(0, 19)}
              &nbsp;·&nbsp;score: <span>{ev.risk_score}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

export default function IncidentTable({ incidents = [] }) {
  const [openId, setOpenId] = useState(null)

  const toggle = (id) => setOpenId(prev => prev === id ? null : id)

  return (
    <div className="table-wrap">
      <div className="table-header">
        <span className="table-header-left">
          Incident Queue
          <span className="opt-tag opt-b" style={{ marginLeft: 8 }}>Option B — Correlation</span>
          <span className="opt-tag opt-a" style={{ marginLeft: 4 }}>Option A — Narrative (click row)</span>
        </span>
        <span className="table-count">{incidents.length} incidents</span>
      </div>

      <table>
        <thead>
          <tr>
            <th>ID</th>
            <th>Severity</th>
            <th>Events</th>
            <th>Principal</th>
            <th>Namespace</th>
            <th>Source</th>
            <th>Start Time</th>
            <th>Signals</th>
          </tr>
        </thead>
        <tbody>
          {incidents.map((inc) => {
            const isOpen = openId === inc.incident_id
            const signals = (inc.triggered_signals || []).join(', ')
            return (
              <>
                <tr
                  key={inc.incident_id}
                  className="inc-row"
                  onClick={() => toggle(inc.incident_id)}
                  style={{ background: isOpen ? 'var(--bg-hover)' : undefined }}
                >
                  <td className="mono" style={{ color: '#94a3b8' }}>
                    {isOpen ? '▾' : '▸'} {inc.incident_id}
                  </td>
                  <td><SevBadge sev={inc.severity} /></td>
                  <td>{inc.event_count}</td>
                  <td className="mono">{inc.principal}</td>
                  <td className="c-ter">{inc.namespace}</td>
                  <td className="c-ter">{inc.source}</td>
                  <td className="c-ter mono">
                    {(inc.start_time || '').slice(0, 19)}
                  </td>
                  <td style={{ fontSize: 11, color: '#64748b', maxWidth: 220 }}>
                    {signals}
                  </td>
                </tr>

                {/* Narrative expansion row */}
                {isOpen && (
                  <tr key={`${inc.incident_id}-narr`}>
                    <td colSpan={8} style={{ padding: '0 8px 12px' }}>
                      <NarrativePanel incident={inc} />
                    </td>
                  </tr>
                )}
              </>
            )
          })}
        </tbody>
      </table>

      {incidents.length === 0 && (
        <p style={{ textAlign: 'center', color: 'var(--text-ter)', padding: 24 }}>
          No incidents found.
        </p>
      )}
    </div>
  )
}
