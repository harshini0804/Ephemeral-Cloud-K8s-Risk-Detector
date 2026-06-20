import {
  ComposedChart, Area, Bar, XAxis, YAxis,
  CartesianGrid, Tooltip, Legend, ResponsiveContainer,
} from 'recharts'

const C1 = '#0E7490'   // color-1 — sky teal (all events area)
const C3 = '#E0E4CC'   // color-3 — warm cream (grid lines)
const C5 = '#FA6900'   // color-5 — vivid orange (risky spikes)

const CustomTooltip = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null
  return (
    <div style={{
      background  : '#FFFFFF',
      border      : '1px solid #A7DBD8',
      borderRadius: 6,
      padding     : '8px 12px',
      fontSize    : 12,
      boxShadow   : '0 2px 8px rgba(0,0,0,0.08)',
    }}>
      <p style={{ color: '#9AA5B4', marginBottom: 4 }}>{label}</p>
      {payload.map((p, i) => (
        <p key={i} style={{ color: p.color }}>
          {p.name}: <strong>{p.value}</strong>
        </p>
      ))}
    </div>
  )
}

export default function BurstTimeline({ data = [] }) {
  const tickFormatter = (val, idx) => idx % 8 === 0 ? val : ''

  return (
    <ResponsiveContainer width="100%" height={240}>
      <ComposedChart data={data} margin={{ top: 4, right: 8, left: -10, bottom: 0 }}>
        <CartesianGrid strokeDasharray="3 3" stroke={C3} />
        <XAxis
          dataKey="minute"
          tick={{ fill: '#9AA5B4', fontSize: 10 }}
          tickFormatter={tickFormatter}
          interval={5}
        />
        <YAxis tick={{ fill: '#9AA5B4', fontSize: 10 }} />
        <Tooltip content={<CustomTooltip />} />
        <Legend
          wrapperStyle={{ fontSize: 11, color: '#4A5568' }}
          iconType="circle"
          iconSize={8}
        />
        <Area
          type="monotone"
          dataKey="all_count"
          name="All events"
          stroke={C1}
          fill={`rgba(105, 210, 231, 0.10)`}
          strokeWidth={2}
          dot={false}
        />
        <Bar
          dataKey="risky_count"
          name="Risky events"
          fill={C5}
          fillOpacity={0.85}
          radius={[2, 2, 0, 0]}
        />
      </ComposedChart>
    </ResponsiveContainer>
  )
}