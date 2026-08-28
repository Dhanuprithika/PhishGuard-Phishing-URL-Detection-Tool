import type { Verdict } from "../types";

interface RiskMeterProps {
  score: number;
  verdict: Verdict;
  size?: "sm" | "md" | "lg";
}

const colors: Record<Verdict, { arc: string; glow: string; text: string }> = {
  safe: { arc: "#16a34a", glow: "#bbf7d0", text: "text-green-600" },
  suspicious: { arc: "#ea580c", glow: "#fed7aa", text: "text-orange-600" },
  phishing: { arc: "#dc2626", glow: "#fecaca", text: "text-red-600" },
};

export default function RiskMeter({ score, verdict, size = "md" }: RiskMeterProps) {
  const { arc, text } = colors[verdict];
  const dim = size === "lg" ? 160 : size === "sm" ? 88 : 120;
  const cx = dim / 2;
  const cy = dim / 2;
  const r = dim * 0.38;
  const strokeW = size === "lg" ? 10 : size === "sm" ? 7 : 9;

  // Arc from 210deg to 330deg (240 degrees sweep)
  const startAngle = 210;
  const sweepAngle = 240;
  const progressAngle = (score / 100) * sweepAngle;

  function polarToCartesian(angle: number) {
    const rad = ((angle - 90) * Math.PI) / 180;
    return {
      x: cx + r * Math.cos(rad),
      y: cy + r * Math.sin(rad),
    };
  }

  function arcPath(start: number, end: number) {
    const s = polarToCartesian(start);
    const e = polarToCartesian(end);
    const large = end - start > 180 ? 1 : 0;
    return `M ${s.x} ${s.y} A ${r} ${r} 0 ${large} 1 ${e.x} ${e.y}`;
  }

  const trackPath = arcPath(startAngle, startAngle + sweepAngle);
  const progressPath = arcPath(startAngle, startAngle + progressAngle);

  const fontSize = size === "lg" ? 36 : size === "sm" ? 22 : 28;
  const labelSize = size === "lg" ? 11 : size === "sm" ? 9 : 10;

  return (
    <div className="flex flex-col items-center gap-1">
      <svg width={dim} height={dim} viewBox={`0 0 ${dim} ${dim}`}>
        <path
          d={trackPath}
          fill="none"
          stroke="#e2e8f4"
          strokeWidth={strokeW}
          strokeLinecap="round"
        />
        {score > 0 && (
          <path
            d={progressPath}
            fill="none"
            stroke={arc}
            strokeWidth={strokeW}
            strokeLinecap="round"
            style={{
              filter: `drop-shadow(0 0 ${strokeW / 2}px ${arc}60)`,
            }}
          />
        )}
        <text
          x={cx}
          y={cy + 6}
          textAnchor="middle"
          dominantBaseline="middle"
          fontSize={fontSize}
          fontWeight="700"
          fontFamily="Outfit, sans-serif"
          fill={arc}
        >
          {score}
        </text>
        <text
          x={cx}
          y={cy + fontSize / 2 + 6}
          textAnchor="middle"
          dominantBaseline="middle"
          fontSize={labelSize}
          fontFamily="Inter, sans-serif"
          fill="#8a9bbf"
        >
          / 100
        </text>
      </svg>
      <span className={`font-mono text-xs font-600 uppercase tracking-widest ${text}`}>
        Risk Score
      </span>
    </div>
  );
}
