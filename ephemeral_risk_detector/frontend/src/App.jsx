import { useState, useEffect } from 'react'
import SummaryCards    from './components/SummaryCards'
import EvalMetrics     from './components/EvalMetrics'
import BurstTimeline   from './components/BurstTimeline'
import TTLHistogram    from './components/TTLHistogram'
import RiskByPrincipal from './components/RiskByPrincipal'
import SeverityPie     from './components/SeverityPie'
import IncidentTable   from './components/IncidentTable'

const API = (path) => fetch(path).then(r => { if (!r.ok) throw new Error(r.status); return r.json() })

export default function App() {
  const [data, setData]     = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError]   = useState(null)

  useEffect(() => {
    Promise.all([
      API('/api/stats'),
      API('/api/evaluate'),
      API('/api/burst-timeline'),
      API('/api/ttl-dist'),
      API('/api/risk-by-principal'),
      API('/api/incidents'),
    ])
    .then(([stats, evalM, timeline, ttl, principal, incidents]) => {
      setData({ stats, evalM, timeline, ttl, principal, incidents })
      setLoading(false)
    })
    .catch(err => {
      setError(`API error: ${err.message} — make sure the FastAPI server is running on port 8000.`)
      setLoading(false)
    })
  }, [])

  if (loading) return (
    <div className="loading-screen">
      <div className="spinner" />
      <p>Loading pipeline results from API…</p>
    </div>
  )

  if (error) return <div className="error-screen">{error}</div>

  const { stats, evalM, timeline, ttl, principal, incidents } = data

  return (
    <>
      {/* ── top bar ── */}
      <header className="topbar">
        <h1>⚡ Ephemeral Cloud &amp; K8s Risk Detector</h1>
        <span className="topbar-right">
          Pipeline run: {new Date().toLocaleTimeString()}
        </span>
      </header>

      <main className="container">

        {/* Phase 3+4+5 KPI cards */}
        <SummaryCards stats={stats} />

        {/* Phase 6 evaluation metrics */}
        <EvalMetrics metrics={evalM} />

        {/* Charts row 1: burst timeline (wide) + TTL histogram */}
        <div className="charts-2col">
          <div className="card">
            <div className="section-title">
              Burst Timeline — Events per 30-min window
            </div>
            <BurstTimeline data={timeline.data} />
          </div>
          <div className="card">
            <div className="section-title">
              TTL Distribution — Ephemeral Resources
            </div>
            <TTLHistogram labels={ttl.labels} counts={ttl.counts} />
          </div>
        </div>

        {/* Charts row 2: risk by principal + severity pie */}
        <div className="charts-equal">
          <div className="card">
            <div className="section-title">
              Cumulative Risk Score — Top 10 Principals
            </div>
            <RiskByPrincipal data={principal.data} />
          </div>
          <div className="card">
            <div className="section-title">
              Severity Distribution
            </div>
            <SeverityPie distribution={stats.severity_distribution} />
          </div>
        </div>

        {/* Incident table with LLM narrative drill-down */}
        <IncidentTable incidents={incidents.incidents || []} />

      </main>
    </>
  )
}
