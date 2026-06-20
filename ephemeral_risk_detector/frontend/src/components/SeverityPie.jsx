import { PieChart, Pie, Cell, Tooltip, Legend, ResponsiveContainer } from 'recharts'

const SEV_COLORS = {
  CRITICAL: '#f87171',
  HIGH    : '#fb923c',
  MEDIUM  : '#fbbf24',
  LOW     : '#4ade80',
  NONE    : '#334155',
}

const CustomTooltip = ({ active, payload }) => {
  if (!active || !payload?.length) return null
  const d = payload[0]
  return (
    <div style={{
      background: '#1e2433', border: '1px solid #3d4a60',
      borderRadius: 6, padding: '8px 12px', fontSize: 12,
    }}>
      <p style={{ color: d.payload.fill }}>{d.name}</p>
      <p style={{ color: '#e2e8f0' }}>Events: <strong>{d.value}</strong></p>
      <p style={{ color: '#94a3b8' }}>{d.payload.pct}%</p>
    </div>
  )
}

export default function SeverityPie({ distribution = {} }) {
  const total = Object.values(distribution).reduce((a, b) => a + b, 0)
  const data  = Object.entries(distribution)
    .filter(([, v]) => v > 0)
    .map(([name, value]) => ({
      name,
      value,
      pct : ((value / total) * 100).toFixed(1),
      fill: SEV_COLORS[name] || '#64748b',
    }))

  return (
    <ResponsiveContainer width="100%" height={240}>
      <PieChart>
        <Pie
          data={data}
          cx="50%"
          cy="50%"
          innerRadius={60}
          outerRadius={90}
          paddingAngle={3}
          dataKey="value"
          label={({ name, pct }) => `${name} ${pct}%`}
          labelLine={{ stroke: '#334155', strokeWidth: 1 }}
        >
          {data.map((d, i) => (
            <Cell key={i} fill={d.fill} stroke="#0f1117" strokeWidth={2} />
          ))}
        </Pie>
        <Tooltip content={<CustomTooltip />} />
        <Legend
          iconType="circle"
          iconSize={8}
          wrapperStyle={{ fontSize: 11, color: '#94a3b8' }}
        />
      </PieChart>
    </ResponsiveContainer>
  )
}
