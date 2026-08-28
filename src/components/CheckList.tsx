import type { CheckItem } from "../types";

const icons = {
  pass: (
    <span className="w-5 h-5 rounded-full bg-green-100 flex items-center justify-center text-green-600 text-xs font-bold flex-shrink-0">
      ✓
    </span>
  ),
  warn: (
    <span className="w-5 h-5 rounded-full bg-orange-100 flex items-center justify-center text-orange-600 text-xs font-bold flex-shrink-0">
      !
    </span>
  ),
  fail: (
    <span className="w-5 h-5 rounded-full bg-red-100 flex items-center justify-center text-red-600 text-xs font-bold flex-shrink-0">
      ✕
    </span>
  ),
  scanning: (
    <span className="w-5 h-5 rounded-full bg-blue-100 flex items-center justify-center flex-shrink-0">
      <span className="w-2.5 h-2.5 rounded-full bg-blue-400 animate-pulse" />
    </span>
  ),
};

export default function CheckList({ checks }: { checks: CheckItem[] }) {
  return (
    <div className="flex flex-col gap-2">
      {checks.map((check, i) => (
        <div
          key={i}
          className="flex items-center gap-3 py-2.5 px-3 bg-white rounded-xl border border-[var(--border)] animate-check-in"
          style={{ animationDelay: `${i * 80}ms`, animationFillMode: "both", opacity: 0 }}
        >
          {icons[check.status]}
          <div className="min-w-0 flex-1">
            <div className="text-sm font-medium text-[var(--foreground)]">{check.label}</div>
            {check.detail && (
              <div className="text-xs text-[var(--muted-foreground)] mt-0.5">{check.detail}</div>
            )}
          </div>
        </div>
      ))}
    </div>
  );
}
