import { useState } from "react";
import type { ScanResult } from "../types";
import VerdictBadge from "../components/VerdictBadge";
import ShieldLogo from "../components/ShieldLogo";

function timeAgo(date: Date): string {
  const diff = Date.now() - date.getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

interface HistoryScreenProps {
  history: ScanResult[];
  onRescan: (url: string) => void;
}

export default function HistoryScreen({ history, onRescan }: HistoryScreenProps) {
  const [search, setSearch] = useState("");
  const [filter, setFilter] = useState<"all" | "safe" | "suspicious" | "phishing">("all");

  const filtered = history.filter((item) => {
    const matchesSearch = item.url.toLowerCase().includes(search.toLowerCase());
    const matchesFilter = filter === "all" || item.verdict === filter;
    return matchesSearch && matchesFilter;
  });

  const counts = {
    safe: history.filter((h) => h.verdict === "safe").length,
    suspicious: history.filter((h) => h.verdict === "suspicious").length,
    phishing: history.filter((h) => h.verdict === "phishing").length,
  };

  return (
    <div className="min-h-screen py-10 px-4">
      <div className="max-w-2xl mx-auto animate-fade-up">
        {/* Header */}
        <div className="mb-6">
          <h1 className="font-display font-700 text-2xl text-[var(--foreground)] mb-1">Scan History</h1>
          <p className="text-sm text-[var(--muted-foreground)]">
            {history.length} URL{history.length !== 1 ? "s" : ""} scanned in this session.
          </p>
        </div>

        {/* Stats row */}
        {history.length > 0 && (
          <div className="grid grid-cols-3 gap-3 mb-5">
            {[
              { label: "Safe", count: counts.safe, color: "text-green-600", bg: "bg-green-50 border-green-200" },
              { label: "Suspicious", count: counts.suspicious, color: "text-orange-600", bg: "bg-orange-50 border-orange-200" },
              { label: "Phishing", count: counts.phishing, color: "text-red-600", bg: "bg-red-50 border-red-200" },
            ].map((s) => (
              <div key={s.label} className={`rounded-2xl border px-4 py-3 ${s.bg}`}>
                <div className={`font-display font-700 text-2xl ${s.color}`}>{s.count}</div>
                <div className="text-xs text-[var(--muted-foreground)] mt-0.5">{s.label}</div>
              </div>
            ))}
          </div>
        )}

        {/* Search + filter */}
        <div className="flex flex-col sm:flex-row gap-3 mb-5">
          <div className="flex-1 flex items-center gap-2 bg-white border border-[var(--border)] rounded-xl px-3 py-2.5 focus-within:border-[var(--primary)] transition-colors">
            <svg className="w-4 h-4 text-[var(--muted-foreground)] flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
              <path strokeLinecap="round" strokeLinejoin="round" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
            </svg>
            <input
              type="text"
              placeholder="Search URLs…"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="flex-1 bg-transparent text-sm text-[var(--foreground)] placeholder:text-[var(--muted-foreground)] outline-none"
            />
            {search && (
              <button onClick={() => setSearch("")} className="text-[var(--muted-foreground)] hover:text-[var(--foreground)] text-xs">
                ✕
              </button>
            )}
          </div>
          <div className="flex gap-1.5 flex-wrap">
            {(["all", "safe", "suspicious", "phishing"] as const).map((f) => (
              <button
                key={f}
                onClick={() => setFilter(f)}
                className={`px-3 py-2 rounded-xl text-xs font-medium capitalize transition-all ${
                  filter === f
                    ? "bg-[var(--primary)] text-white shadow-sm"
                    : "bg-white border border-[var(--border)] text-[var(--muted-foreground)] hover:text-[var(--foreground)]"
                }`}
              >
                {f}
              </button>
            ))}
          </div>
        </div>

        {/* Empty states */}
        {history.length === 0 ? (
          <div className="text-center py-20 bg-white rounded-2xl border border-[var(--border)]">
            <div className="flex justify-center mb-4 opacity-30">
              <ShieldLogo size={48} />
            </div>
            <p className="font-display font-600 text-[var(--foreground)] mb-1">No scans yet</p>
            <p className="text-sm text-[var(--muted-foreground)]">
              Paste a URL in the scanner to get started.
            </p>
          </div>
        ) : filtered.length === 0 ? (
          <div className="text-center py-16 bg-white rounded-2xl border border-[var(--border)]">
            <p className="font-medium text-[var(--foreground)] mb-1">No matching results</p>
            <p className="text-sm text-[var(--muted-foreground)]">
              Try a different search term or filter.
            </p>
          </div>
        ) : (
          <div className="flex flex-col gap-2.5">
            {filtered.map((item, i) => (
              <div
                key={i}
                className="bg-white rounded-2xl border border-[var(--border)] hover:border-blue-200 hover:shadow-sm transition-all duration-150 p-4 flex items-center gap-4 group"
              >
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1.5 flex-wrap">
                    <VerdictBadge verdict={item.verdict} size="sm" />
                    <span className="font-mono text-xs text-[var(--muted-foreground)]">
                      {timeAgo(item.scannedAt)}
                    </span>
                  </div>
                  <p className="text-sm font-mono text-[var(--foreground)] truncate">{item.url}</p>
                  {item.indicators.length > 0 && (
                    <p className="text-xs text-[var(--muted-foreground)] mt-1">
                      {item.indicators[0]}
                      {item.indicators.length > 1 && (
                        <span className="ml-1 text-[var(--muted-foreground)]">
                          +{item.indicators.length - 1} more
                        </span>
                      )}
                    </p>
                  )}
                </div>
                <div className="flex items-center gap-3 flex-shrink-0">
                  <div className="text-right">
                    <div
                      className={`font-display font-700 text-xl leading-none ${
                        item.verdict === "safe"
                          ? "text-green-600"
                          : item.verdict === "suspicious"
                            ? "text-orange-600"
                            : "text-red-600"
                      }`}
                    >
                      {item.riskScore}
                    </div>
                    <div className="text-[10px] font-mono text-[var(--muted-foreground)] uppercase tracking-wide">
                      /100
                    </div>
                  </div>
                  <button
                    onClick={() => onRescan(item.url)}
                    className="opacity-0 group-hover:opacity-100 transition-opacity bg-[var(--secondary)] hover:bg-[var(--primary)] hover:text-white text-[var(--primary)] text-xs font-medium rounded-lg px-2.5 py-1.5"
                  >
                    Rescan
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
