export default function SummaryCards({ stats }) {
  const cards = [
    { val: stats.total_events.toLocaleString(), lbl: 'Total Events',       cls: 'c-blue'   },
    { val: stats.ephemeral_count.toLocaleString(), lbl: 'Ephemeral Assets', cls: 'c-purple' },
    { val: stats.critical_incidents, lbl: 'CRITICAL Incidents',             cls: 'c-crit'   },
    { val: stats.high_incidents,     lbl: 'HIGH Incidents',                 cls: 'c-high'   },
    { val: stats.alert_reduction_pct + '%', lbl: 'Alert Reduction',         cls: 'c-low'    },
    { val: stats.noise_suppression_pct + '%', lbl: 'Noise Suppressed',      cls: 'c-low'    },
  ]

  return (
    <div className="cards-grid" style={{ marginBottom: 16 }}>
      {cards.map((c, i) => (
        <div key={i} className="card">
          <div className={`card-val ${c.cls}`}>{c.val}</div>
          <div className="card-lbl">{c.lbl}</div>
        </div>
      ))}
    </div>
  )
}
