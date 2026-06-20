import { PieChart, Pie, Cell, Tooltip, Legend, ResponsiveContainer } from 'recharts'

const SEV_COLORS = {
  CRITICAL: '#fa0000',
  HIGH    : '#f39830',
  MEDIUM  : '#c7ba08',
  LOW     : '#69D2E7',
  NONE    : '#9ba07f',
}

const CustomTooltip = ({ active, payload }) => {
  if (!active || !payload?.length) return null
  const d = payload[0]
  return (
    <div style={{
      background  : '#FFFFFF',
      border      : '1px solid #A7DBD8',
      borderRadius: 6,
      padding     : '8px 12px',
      fontSize    : 12,
      boxShadow   : '0 2px 8px rgba(0,0,0,0.08)',
    }}>
      <p style={{ color: d.payload.fill, fontWeight: 600 }}>{d.name}</p>
      <p style={{ color: '#4A5568' }}>Events: <strong>{d.value}</strong></p>
      <p style={{ color: '#9AA5B4' }}>{d.payload.pct}%</p>
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
      fill: SEV_COLORS[name] || '#9ba07f',
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
          paddingAngle={0}
          minAngle={6}
          dataKey="value"
        >
          {data.map((d, i) => (
            <Cell key={i} fill={d.fill} stroke="#FFFFFF" strokeWidth={2} />
          ))}
        </Pie>

        <Tooltip content={<CustomTooltip />} />

        <Legend
          iconType="circle"
          iconSize={8}
          wrapperStyle={{ fontSize: 11, color: '#4A5568', paddingTop: 12 }}
          formatter={(value, entry) =>
            `${value}  —  ${entry.payload.pct}%`
          }
        />
      </PieChart>
    </ResponsiveContainer>
  )
}