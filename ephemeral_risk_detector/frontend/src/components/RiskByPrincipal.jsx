import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Cell,
  ResponsiveContainer,
} from "recharts";

// Rank 1 = color-5 (vivid orange), rank 2 = color-4, rest fade through color-1 → color-2
const BAR_COLORS = [
  "#C2410C", // color-5 — rank 1 (most critical)
  "#EA580C", // color-4 — rank 2
  "#0E7490",
  "#1A7D8F",
  "#208D9E",
  "#2B9DB3",
  "#3AACBF",
  "#155E75",
  "#186070",
  "#1A6678",
];

const CustomTooltip = ({ active, payload }) => {
  if (!active || !payload?.length) return null;
  return (
    <div
      style={{
        background: "#FFFFFF",
        border: "1px solid #A7DBD8",
        borderRadius: 6,
        padding: "8px 12px",
        fontSize: 12,
        boxShadow: "0 2px 8px rgba(0,0,0,0.08)",
      }}
    >
      <p style={{ color: "#9AA5B4", marginBottom: 2 }}>
        {payload[0].payload.name}
      </p>
      <p style={{ color: "#FA6900" }}>
        Score: <strong>{payload[0].value}</strong>
      </p>
    </div>
  );
};

export default function RiskByPrincipal({ data = [] }) {
  const sorted = [...data].reverse();

  return (
    <ResponsiveContainer width="100%" height={240}>
      <BarChart
        data={sorted}
        layout="vertical"
        margin={{ top: 4, right: 16, left: 0, bottom: 0 }}
      >
        <CartesianGrid
          strokeDasharray="3 3"
          stroke="#E0E4CC"
          horizontal={false}
        />
        <XAxis type="number" tick={{ fill: "#9AA5B4", fontSize: 10 }} />
        <YAxis
          type="category"
          dataKey="name"
          width={140}
          tick={{ fill: "#4A5568", fontSize: 11, fontFamily: "monospace" }}
        />
        <Tooltip content={<CustomTooltip />} />
        <Bar dataKey="score" radius={[0, 4, 4, 0]}>
          {sorted.map((_, i) => (
            <Cell
              key={i}
              fill={BAR_COLORS[sorted.length - 1 - i] || "#A7DBD8"}
            />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}
