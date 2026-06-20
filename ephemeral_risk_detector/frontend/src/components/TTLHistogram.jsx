import {
  BarChart, Bar, XAxis, YAxis,
  CartesianGrid, Tooltip, ResponsiveContainer,
} from 'recharts'

const C2 = '#155E75'   // color-2 — sage teal (bars)
const C3 = '#E0E4CC'   // color-3 — warm cream (grid)

const CustomTooltip = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null
  return (
    <div style={{
      background  : '#FFFFFF',
      border      : '1px solid #0E7490',
      borderRadius: 6,
      padding     : '8px 12px',
      fontSize    : 12,
      boxShadow   : '0 2px 8px rgba(0,0,0,0.08)',
    }}>
      <p style={{ color: '#9AA5B4' }}>TTL: {label} min</p>
      <p style={{ color: '#2B9DB3' }}>Count: <strong>{payload[0].value}</strong></p>
    </div>
  )
}

export default function TTLHistogram({ labels = [], counts = [] }) {
  const data = labels.map((l, i) => ({ bin: l, count: counts[i] || 0 }))

  return (
    <ResponsiveContainer width="100%" height={240}>
      <BarChart data={data} margin={{ top: 4, right: 8, left: -10, bottom: 0 }}>
        <CartesianGrid strokeDasharray="3 3" stroke={C3} />
        <XAxis
          dataKey="bin"
          tick={{ fill: '#9AA5B4', fontSize: 9 }}
          interval={3}
          angle={-30}
          textAnchor="end"
          height={36}
        />
        <YAxis tick={{ fill: '#9AA5B4', fontSize: 10 }} />
        <Tooltip content={<CustomTooltip />} />
        <Bar
          dataKey="count"
          name="Resources"
          fill={C2}
          fillOpacity={0.9}
          radius={[3, 3, 0, 0]}
        />
      </BarChart>
    </ResponsiveContainer>
  )
}