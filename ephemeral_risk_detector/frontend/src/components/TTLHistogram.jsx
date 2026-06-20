import {
  BarChart, Bar, XAxis, YAxis,
  CartesianGrid, Tooltip, ResponsiveContainer,
} from 'recharts'

const CustomTooltip = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null
  return (
    <div style={{
      background: '#1e2433', border: '1px solid #3d4a60',
      borderRadius: 6, padding: '8px 12px', fontSize: 12,
    }}>
      <p style={{ color: '#94a3b8' }}>TTL: {label} min</p>
      <p style={{ color: '#a78bfa' }}>Count: <strong>{payload[0].value}</strong></p>
    </div>
  )
}

export default function TTLHistogram({ labels = [], counts = [] }) {
  const data = labels.map((l, i) => ({ bin: l, count: counts[i] || 0 }))

  return (
    <ResponsiveContainer width="100%" height={240}>
      <BarChart data={data} margin={{ top: 4, right: 8, left: -10, bottom: 0 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="#1e2433" />
        <XAxis
          dataKey="bin"
          tick={{ fill: '#64748b', fontSize: 9 }}
          interval={3}
          angle={-30}
          textAnchor="end"
          height={36}
        />
        <YAxis tick={{ fill: '#64748b', fontSize: 10 }} />
        <Tooltip content={<CustomTooltip />} />
        <Bar
          dataKey="count"
          name="Resources"
          fill="#a78bfa"
          fillOpacity={0.8}
          radius={[3, 3, 0, 0]}
        />
      </BarChart>
    </ResponsiveContainer>
  )
}
