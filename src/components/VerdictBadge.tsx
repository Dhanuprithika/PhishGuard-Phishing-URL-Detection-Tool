import type { Verdict } from "../types";

const config: Record<
  Verdict,
  { label: string; icon: string; bg: string; text: string; ring: string }
> = {
  safe: {
    label: "SAFE",
    icon: "●",
    bg: "bg-green-50",
    text: "text-green-700",
    ring: "ring-green-200",
  },
  suspicious: {
    label: "SUSPICIOUS",
    icon: "▲",
    bg: "bg-orange-50",
    text: "text-orange-700",
    ring: "ring-orange-200",
  },
  phishing: {
    label: "HIGH RISK",
    icon: "✕",
    bg: "bg-red-50",
    text: "text-red-700",
    ring: "ring-red-200",
  },
};

export default function VerdictBadge({
  verdict,
  size = "md",
}: {
  verdict: Verdict;
  size?: "sm" | "md" | "lg";
}) {
  const c = config[verdict];
  const textSize =
    size === "lg"
      ? "text-sm tracking-widest"
      : size === "sm"
        ? "text-[10px] tracking-wider"
        : "text-xs tracking-widest";
  const padding = size === "lg" ? "px-4 py-2" : size === "sm" ? "px-2 py-0.5" : "px-3 py-1";
  const iconSize = size === "lg" ? "text-base" : "text-xs";

  return (
    <span
      className={`inline-flex items-center gap-1.5 font-mono font-600 uppercase rounded-full ring-1 ${c.bg} ${c.text} ${c.ring} ${textSize} ${padding}`}
    >
      <span className={iconSize}>{c.icon}</span>
      {c.label}
    </span>
  );
}
