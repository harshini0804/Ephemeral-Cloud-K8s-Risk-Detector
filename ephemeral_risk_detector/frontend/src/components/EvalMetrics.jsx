export default function EvalMetrics({ metrics }) {
  if (!metrics) return null
  const t = metrics.targets_met || {}

  const rows = [
    { val: (metrics.precision * 100).toFixed(1) + '%', lbl: 'Precision',       sub: '> 75%',  pass: t.precision_target        },
    { val: (metrics.recall    * 100).toFixed(1) + '%', lbl: 'Recall',          sub: '> 70%',  pass: t.recall_target           },
    { val: metrics.f1_score.toFixed(3),                lbl: 'F1 Score',        sub: '> 0.72', pass: t.f1_target               },
    { val: metrics.critical_recall_pct + '%',          lbl: 'CRITICAL Recall', sub: '≥ 95%',  pass: t.critical_recall_target  },
    { val: metrics.alert_reduction_pct + '%',          lbl: 'Alert Reduction', sub: '≥ 40%',  pass: t.alert_reduction_target  },
    { val: metrics.noise_suppression_pct + '%',        lbl: 'Noise Suppr.',    sub: '≥ 90%',  pass: t.noise_suppression_target},
  ]

  return (
    <div className="eval-grid" style={{ marginBottom: 16 }}>
      {rows.map((r, i) => (
        <div key={i} className="eval-card">
          <div className={`eval-val ${r.pass ? 'pass' : 'fail'}`}>{r.val}</div>
          <div className="eval-lbl">{r.lbl}</div>
          <div className={`eval-sub ${r.pass ? 'pass' : 'fail'}`}>
            {r.pass ? '✓' : '✗'} target {r.sub}
          </div>
        </div>
      ))}
    </div>
  )
}
