import { useState } from 'react'

function SevBadge({ sev }) {
  return <span className={`sev sev-${sev}`}>{sev}</span>
}

// ── Inline markdown renderer ──────────────────────────────────────────────────
function renderInline(str) {
  const parts = str.split(/(\*\*[^*]+\*\*|`[^`]+`)/)
  return parts.map((part, i) => {
    if (part.startsWith('**') && part.endsWith('**'))
      return <strong key={i}>{part.slice(2, -2)}</strong>
    if (part.startsWith('`') && part.endsWith('`'))
      return (
        <code key={i} style={{
          background  : 'rgba(224, 228, 204, 0.65)',
          padding     : '1px 5px',
          borderRadius: 3,
          fontSize    : 11,
          fontFamily  : 'SF Mono, Fira Code, monospace',
          color       : '#EA580C',
        }}>
          {part.slice(1, -1)}
        </code>
      )
    return part
  })
}

function MarkdownNarrative({ text }) {
  if (!text) return <p style={{ color: '#9AA5B4' }}>No narrative available.</p>

  const lines = text.split('\n').filter(l => l.trim())

  return (
    <div>
      {lines.map((line, i) => {
        // Numbered action item: "  1. **Immediate:** ..."
        if (/^\s+\d+\./.test(line)) {
          const trimmed = line.trim()
          return (
            <div key={i} style={{
              display   : 'flex',
              gap       : 8,
              marginBottom: 6,
              paddingLeft : 12,
              color     : '#4A5568',
            }}>
              <span style={{ color: '#000000', flexShrink: 0 }}>
                {trimmed.match(/^\d+\./)?.[0]}
              </span>
              <span>{renderInline(trimmed.replace(/^\d+\.\s*/, ''))}</span>
            </div>
          )
        }

        // Bullet line: "* **When:** ..."
        if (line.startsWith('* ')) {
          const content    = line.slice(2)
          const labelMatch = content.match(/^\*\*([^*]+)\*\*:?\s*(.*)$/)

          if (labelMatch) {
            return (
              <div key={i} style={{
                display              : 'grid',
                gridTemplateColumns  : '120px 1fr',
                gap                  : 8,
                marginBottom         : 10,
                alignItems           : 'flex-start',
              }}>
                <span style={{
                  color     : '#0E7490',
                  fontWeight: 600,
                  fontSize  : 12,
                  paddingTop: 1,
                }}>
                  {labelMatch[1]}
                </span>
                <span style={{ color: '#4A5568', fontSize: 13, lineHeight: 1.6 }}>
                  {renderInline(labelMatch[2])}
                </span>
              </div>
            )
          }

          return (
            <div key={i} style={{ marginBottom: 8, color: '#4A5568', fontSize: 13 }}>
              {renderInline(content)}
            </div>
          )
        }

        return (
          <div key={i} style={{ marginBottom: 6, color: '#4A5568', fontSize: 13 }}>
            {renderInline(line)}
          </div>
        )
      })}
    </div>
  )
}

// ── Narrative panel (Option A) ────────────────────────────────────────────────
function NarrativePanel({ incident }) {
  const mitre       = Object.entries(incident.mitre_techniques || {})
  const isLLM       = incident.narrative_source === 'llm'
  const sourceLabel = isLLM ? '✓ Groq LLM' : '⚠ Template Fallback'
  const sourceBg    = isLLM ? 'rgba(105, 210, 231, 0.12)' : 'rgba(224, 228, 204, 0.5)'
  const sourceColor = isLLM ? '#2B9DB3'                    : '#9AA5B4'
  const sourceBorder= isLLM ? 'rgba(105, 210, 231, 0.45)'  : 'rgba(167, 219, 216, 0.4)'

  return (
    <div className="narrative-panel">

      {/* Header row */}
      <div className="narrative-hdr">
        <span>🤖 AI-GENERATED ANALYST NARRATIVE</span>
        <span style={{
          marginLeft  : 'auto',
          fontSize    : 10,
          padding     : '2px 9px',
          borderRadius: 999,
          border      : `1px solid ${sourceBorder}`,
          background  : sourceBg,
          color       : sourceColor,
          fontWeight  : 600,
        }}>
          {sourceLabel}
        </span>
      </div>

      {/* Rendered narrative */}
      <MarkdownNarrative text={incident.narrative} />

      {/* MITRE chips */}
      {mitre.length > 0 && (
        <div className="mitre-chips">
          {mitre.map(([code, name]) => (
            <span key={code} className="mitre-chip">{code} — {name}</span>
          ))}
        </div>
      )}

      {/* Evidence events */}
      {incident.evidence?.length > 0 && (
        <div className="evidence-section">
          <div className="evidence-title">RAW EVIDENCE EVENTS (first 5)</div>
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

// ── Main table ────────────────────────────────────────────────────────────────
export default function IncidentTable({ incidents = [] }) {
  const [openId, setOpenId] = useState(null)
  const toggle = (id) => setOpenId(prev => prev === id ? null : id)

  return (
    <div className="table-wrap">
      <div className="table-header">
        <span className="table-header-left">
          Incident Queue
          <span className="opt-tag opt-a" style={{ marginLeft: 4 }}>
            Narrative (click row to expand)
          </span>
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
            const isOpen  = openId === inc.incident_id
            const signals = (inc.triggered_signals || []).join(', ')
            const isLLM   = inc.narrative_source === 'llm'

            return (
              <>
                <tr
                  key={inc.incident_id}
                  className="inc-row"
                  onClick={() => toggle(inc.incident_id)}
                  style={{ background: isOpen ? 'rgba(167, 219, 216, 0.10)' : undefined }}
                >
                  <td className="mono" style={{ color: '#000000' }}>
                    <span style={{ marginRight: 6 }}>{isOpen ? '▾' : '▸'}</span>
                    {inc.incident_id}
                    {/* LLM / template indicator dot */}
                    <span style={{
                      display       : 'inline-block',
                      width         : 6,
                      height        : 6,
                      borderRadius  : '50%',
                      marginLeft    : 6,
                      background    : isLLM ? '#69D2E7' : '#EA580C',
                      verticalAlign : 'middle',
                    }} />
                  </td>
                  <td><SevBadge sev={inc.severity} /></td>
                  <td>{inc.event_count}</td>
                  <td className="mono">{inc.principal}</td>
                  <td className="c-ter">{inc.namespace}</td>
                  <td className="c-ter">{inc.source}</td>
                  <td className="c-ter mono">{(inc.start_time || '').slice(0, 19)}</td>
                  <td style={{ fontSize: 11, color: '#000000', maxWidth: 220 }}>
                    {signals}
                  </td>
                </tr>

                {isOpen && (
                  <tr key={`${inc.incident_id}-narr`}>
                    <td colSpan={8} style={{ padding: '0 8px 14px' }}>
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
        <p style={{ textAlign: 'center', color: '#000000', padding: 24 }}>
          No incidents found.
        </p>
      )}

      {/* Legend */}
      <div style={{
        marginTop: 12,
        display  : 'flex',
        gap      : 16,
        fontSize : 11,
        color    : '#000000',
      }}>
        <span>
          <span style={{
            display      : 'inline-block',
            width        : 6,
            height       : 6,
            borderRadius : '50%',
            background   : '#69D2E7',
            marginRight  : 5,
            verticalAlign: 'middle',
          }} />
          Groq LLM narrative
        </span>
        <span>
          <span style={{
            display      : 'inline-block',
            width        : 6,
            height       : 6,
            borderRadius : '50%',
            background   : '#EA580C',
            marginRight  : 5,
            verticalAlign: 'middle',
          }} />
          Template narrative
        </span>
      </div>
    </div>
  )
}