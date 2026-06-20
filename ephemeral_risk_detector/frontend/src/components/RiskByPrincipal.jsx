import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid,
  Tooltip, Cell, ResponsiveContainer,
} from 'recharts'

const BAR_COLORS = ['#f87171','#fb923c','#fbbf24','#60a5fa','#60a5fa',
                    '#60a5fa','#60a5fa','#60a5fa','#60a5fa','#60a5fa']

const CustomTooltip = ({ active, payload }) => {
  if (!active || !payload?.length) return null
  return (
    <div style={{
      background: '#1e2433', border: '1px solid #3d4a60',
      borderRadius: 6, padding: '8px 12px', fontSize: 12,
    }}>
      <p style={{ color: '#94a3b8' }}>{payload[0].payload.name}</p>
      <p style={{ color: '#f87171' }}>Score: <strong>{payload[0].value}</strong></p>
    </div>
  )
}

export default function RiskByPrincipal({ data = [] }) {
  // Reverse for horizontal bar (highest at top)
  const sorted = [...data].reverse()

  return (
    <ResponsiveContainer width="100%" height={240}>
      <BarChart
        data={sorted}
        layout="vertical"
        margin={{ top: 4, right: 16, left: 0, bottom: 0 }}
      >
        <CartesianGrid strokeDasharray="3 3" stroke="#1e2433" horizontal={false} />
        <XAxis type="number" tick={{ fill: '#64748b', fontSize: 10 }} />
        <YAxis
          type="category"
          dataKey="name"
          width={140}
          tick={{ fill: '#94a3b8', fontSize: 11, fontFamily: 'monospace' }}
        />
        <Tooltip content={<CustomTooltip />} />
        <Bar dataKey="score" radius={[0, 4, 4, 0]}>
          {sorted.map((_, i) => (
            <Cell
              key={i}
              fill={BAR_COLORS[sorted.length - 1 - i] || '#60a5fa'}
            />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  )
}
