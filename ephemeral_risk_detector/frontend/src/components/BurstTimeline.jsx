import {
  ComposedChart, Area, Bar, XAxis, YAxis,
  CartesianGrid, Tooltip, Legend, ResponsiveContainer,
} from 'recharts'

const COLORS = {
  all  : '#60a5fa',
  risky: '#f87171',
}

const CustomTooltip = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null
  return (
    <div style={{
      background: '#1e2433', border: '1px solid #3d4a60',
      borderRadius: 6, padding: '8px 12px', fontSize: 12,
    }}>
      <p style={{ color: '#94a3b8', marginBottom: 4 }}>{label}</p>
      {payload.map((p, i) => (
        <p key={i} style={{ color: p.color }}>
          {p.name}: <strong>{p.value}</strong>
        </p>
      ))}
    </div>
  )
}

export default function BurstTimeline({ data = [] }) {
  // Show every 8th label to avoid overcrowding
  const tickFormatter = (val, idx) => idx % 8 === 0 ? val : ''

  return (
    <ResponsiveContainer width="100%" height={240}>
      <ComposedChart data={data} margin={{ top: 4, right: 8, left: -10, bottom: 0 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="#1e2433" />
        <XAxis
          dataKey="minute"
          tick={{ fill: '#64748b', fontSize: 10 }}
          tickFormatter={tickFormatter}
          interval={0}
        />
        <YAxis tick={{ fill: '#64748b', fontSize: 10 }} />
        <Tooltip content={<CustomTooltip />} />
        <Legend
          wrapperStyle={{ fontSize: 11, color: '#94a3b8' }}
          iconType="circle"
          iconSize={8}
        />
        <Area
          type="monotone"
          dataKey="all_count"
          name="All events"
          stroke={COLORS.all}
          fill="rgba(96,165,250,0.08)"
          strokeWidth={1.5}
          dot={false}
        />
        <Bar
          dataKey="risky_count"
          name="Risky events"
          fill={COLORS.risky}
          fillOpacity={0.85}
          radius={[2, 2, 0, 0]}
        />
      </ComposedChart>
    </ResponsiveContainer>
  )
}
