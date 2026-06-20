import { useState } from 'react'

// ── Palette constants ─────────────────────────────────────────────
const C1 = '#69D2E7'   // color-1 teal  → narrative header, labels, LLM badge
const C2 = '#A7DBD8'   // color-2 sage  → MITRE chips, borders
const C3 = '#E0E4CC'   // color-3 cream → code span bg, template badge bg
const C4 = '#F38630'   // color-4 amber → code span text (warm, readable)
const C5 = '#FA6900'   // color-5 orange → not used directly here

// ── Severity badge ────────────────────────────────────────────────
function SevBadge({ sev }) {
  return <span className={`sev sev-${sev}`}>{sev}</span>
}

// ── Inline markdown renderer ──────────────────────────────────────
// Handles **bold**, `code`, bullet "* " lines, and numbered "  1. " lines.
// No external dependency — avoids adding react-markdown to package.json.
function renderInline(str) {
  const parts = str.split(/(\*\*[^*]+\*\*|`[^`]+`)/)
  return parts.map((part, i) => {
    if (part.startsWith('**') && part.endsWith('**'))
      return <strong key={i} style={{ color: '#1A1F2E' }}>{part.slice(2, -2)}</strong>
    if (part.startsWith('`') && part.endsWith('`'))
      return (
        <code key={i} style={{
          background  : C3,
          color       : C4,
          padding     : '1px 5px',
          borderRadius: 3,
          fontSize    : 11,
          fontFamily  : 'SF Mono, Fira Code, monospace',
          fontWeight  : 500,
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
        // Numbered action line: "  1. **Immediate:** ..."
        if (/^\s+\d+\./.test(line)) {
          const trimmed = line.trim()
          const num     = trimmed.match(/^\d+\./)?.[0]
          const rest    = trimmed.replace(/^\d+\.\s*/, '')
          return (
            <div key={i} style={{
              display      : 'flex',
              gap          : 8,
              marginBottom : 6,
              paddingLeft  : 14,
              color        : '#4A5568',
            }}>
              <span style={{ color: C2, flexShrink: 0, fontWeight: 600 }}>{num}</span>
              <span>{renderInline(rest)}</span>
            </div>
          )
        }

        // Bullet line: "* **When:** ..." or "* **Action Required:**"
        if (line.startsWith('* ')) {
          const content    = line.slice(2)
          const labelMatch = content.match(/^\*\*([^*]+)\*\*:?\s*(.*)$/)

          if (labelMatch) {
            return (
              <div key={i} style={{
                display             : 'grid',
                gridTemplateColumns : '120px 1fr',
                gap                 : 10,
                marginBottom        : 10,
                alignItems          : 'flex-start',
              }}>
                <span style={{
                  color      : C1,
                  fontWeight : 700,
                  fontSize   : 11,
                  paddingTop : 2,
                  textTransform: 'uppercase',
                  letterSpacing: '0.04em',
                }}>
                  {labelMatch[1]}
                </span>
                <span style={{ color: '#4A5568', fontSize: 13, lineHeight: 1.65 }}>
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

        // Plain line
        return (
          <div key={i} style={{ marginBottom: 6, color: '#4A5568', fontSize: 13 }}>
            {renderInline(line)}
          </div>
        )
      })}
    </div>
  )
}

// ── Narrative panel (Option A) ────────────────────────────────────
function NarrativePanel({ incident }) {
  const mitre    = Object.entries(incident.mitre_techniques || {})
  const isLLM    = incident.narrative_source === 'llm'

  return (
    <div className="narrative-panel">

      {/* Header */}
      <div className="narrative-hdr">
        <span>🔍 Analyst Narrative</span>
        <span className="opt-tag opt-a">Option A — Groq LLM</span>
        {/* LLM vs Template badge */}
        <span style={{
          marginLeft  : 'auto',
          fontSize    : 10,
          fontWeight  : 600,
          padding     : '2px 9px',
          borderRadius: 999,
          background  : isLLM
            ? 'rgba(105, 210, 231, 0.14)'
            : 'rgba(224, 228, 204, 0.60)',
          color       : isLLM ? '#1A8FA3' : '#9AA5B4',
          border      : `1px solid ${isLLM
            ? 'rgba(105, 210, 231, 0.40)'
            : 'rgba(167, 219, 216, 0.40)'}`,
        }}>
          {isLLM ? '✓ Groq LLM' : '⚠ Template Fallback'}
        </span>
      </div>

      {/* Narrative body */}
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
          <div className="evidence-title">Raw Evidence Events (first 5)</div>
          {incident.evidence.map((ev, i) => (
            <div key={i} className="evidence-row">
              <span>{ev.event_id}</span>
              &nbsp;·&nbsp;{ev.event_type}
              &nbsp;·&nbsp;{ev.timestamp?.slice(0, 19)}
              &nbsp;·&nbsp;score:&nbsp;<span>{ev.risk_score}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

// ── Main incident table ───────────────────────────────────────────
export default function IncidentTable({ incidents = [] }) {
  const [openId, setOpenId] = useState(null)
  const toggle = (id) => setOpenId(prev => prev === id ? null : id)

  return (
    <div className="table-wrap">
      <div className="table-header">
        <span className="table-header-left">
          Incident Queue
          <span className="opt-tag opt-b" style={{ marginLeft: 8 }}>
            Option B — Correlation
          </span>
          <span className="opt-tag opt-a" style={{ marginLeft: 4 }}>
            Option A — Narrative
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
                  style={{ background: isOpen ? 'rgba(224,228,204,0.30)' : undefined }}
                >
                  <td style={{ color: '#4A5568' }} className="mono">
                    <span style={{
                      marginRight : 6,
                      color       : C1,
                      fontWeight  : 700,
                      fontSize    : 11,
                    }}>
                      {isOpen ? '▾' : '▸'}
                    </span>
                    {inc.incident_id}
                    {/* Dot indicator: green = LLM, muted = template */}
                    <span style={{
                      display       : 'inline-block',
                      width         : 5,
                      height        : 5,
                      borderRadius  : '50%',
                      marginLeft    : 6,
                      background    : isLLM ? C1 : '#C7D0D8',
                      verticalAlign : 'middle',
                    }} title={isLLM ? 'LLM narrative' : 'Template narrative'} />
                  </td>
                  <td><SevBadge sev={inc.severity} /></td>
                  <td style={{ color: '#1A1F2E', fontWeight: 600 }}>
                    {inc.event_count}
                  </td>
                  <td className="mono" style={{ color: '#4A5568' }}>
                    {inc.principal}
                  </td>
                  <td className="c-ter">{inc.namespace}</td>
                  <td className="c-ter">{inc.source}</td>
                  <td className="c-ter mono" style={{ fontSize: 12 }}>
                    {(inc.start_time || '').slice(0, 19)}
                  </td>
                  <td style={{ fontSize: 11, color: '#9AA5B4', maxWidth: 220 }}>
                    {signals}
                  </td>
                </tr>

                {isOpen && (
                  <tr key={`${inc.incident_id}-narr`}>
                    <td colSpan={8} style={{ padding: '0 10px 14px' }}>
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
        <p style={{
          textAlign : 'center',
          color     : '#9AA5B4',
          padding   : 32,
          fontSize  : 13,
        }}>
          No incidents found.
        </p>
      )}

      {/* Legend */}
      <div style={{
        marginTop  : 14,
        display    : 'flex',
        gap        : 18,
        fontSize   : 11,
        color      : '#9AA5B4',
        borderTop  : '1px solid rgba(224,228,204,0.60)',
        paddingTop : 10,
      }}>
        <span>
          <span style={{
            display       : 'inline-block',
            width         : 5,
            height        : 5,
            borderRadius  : '50%',
            background    : C1,
            marginRight   : 5,
            verticalAlign : 'middle',
          }} />
          Groq LLM narrative
        </span>
        <span>
          <span style={{
            display       : 'inline-block',
            width         : 5,
            height        : 5,
            borderRadius  : '50%',
            background    : '#C7D0D8',
            marginRight   : 5,
            verticalAlign : 'middle',
          }} />
          Template fallback
        </span>
        <span style={{ marginLeft: 'auto' }}>
          Click any row to expand the analyst narrative
        </span>
      </div>
    </div>
  )
}
