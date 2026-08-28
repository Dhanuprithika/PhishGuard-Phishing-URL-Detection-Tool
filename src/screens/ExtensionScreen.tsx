import { useState } from "react";
import ShieldLogo from "../components/ShieldLogo";
import RiskMeter from "../components/RiskMeter";
import VerdictBadge from "../components/VerdictBadge";
import type { Verdict } from "../types";

type ExtState = "idle" | "scanning" | "done";

const DEMO_SITES: { url: string; verdict: Verdict; score: number; summary: string }[] = [
  {
    url: "https://github.com",
    verdict: "safe",
    score: 5,
    summary: "Trusted developer platform with verified TLS and clean reputation.",
  },
  {
    url: "https://dropbox-share.files.net",
    verdict: "suspicious",
    score: 64,
    summary: "Brand impersonation detected. Not affiliated with Dropbox Inc.",
  },
  {
    url: "http://paypa1-login.verify.tk",
    verdict: "phishing",
    score: 93,
    summary: "Known phishing domain. Credential harvesting site targeting PayPal.",
  },
];

const verdictColors: Record<Verdict, { bar: string; bg: string }> = {
  safe: { bar: "bg-green-500", bg: "bg-green-50" },
  suspicious: { bar: "bg-orange-400", bg: "bg-orange-50" },
  phishing: { bar: "bg-red-500", bg: "bg-red-50" },
};

export default function ExtensionScreen({ onViewReport }: { onViewReport: () => void }) {
  const [demoIdx, setDemoIdx] = useState(0);
  const [state, setState] = useState<ExtState>("idle");
  const demo = DEMO_SITES[demoIdx];

  function scan() {
    setState("scanning");
    setTimeout(() => setState("done"), 1800);
  }

  function reset() {
    setState("idle");
  }

  return (
    <div className="min-h-screen py-10 px-4 flex flex-col items-center">
      <div className="max-w-2xl w-full animate-fade-up">
        <div className="mb-8">
          <h1 className="font-display font-700 text-2xl text-[var(--foreground)] mb-1">
            Browser Extension
          </h1>
          <p className="text-sm text-[var(--muted-foreground)]">
            PhishGuard detects threats directly in your browser. Preview the extension popup below.
          </p>
        </div>

        <div className="flex flex-col lg:flex-row gap-8 items-start">
          {/* Popup preview */}
          <div className="w-[360px] mx-auto lg:mx-0 rounded-2xl border-2 border-[var(--border)] shadow-xl overflow-hidden bg-white">
            {/* Extension header */}
            <div className="bg-[var(--foreground)] px-4 py-3 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <ShieldLogo size={20} />
                <span className="font-display font-700 text-[15px] text-white tracking-tight">
                  Phish<span className="text-blue-400">Guard</span>
                </span>
              </div>
              <div className="flex gap-1.5">
                <div className="w-2.5 h-2.5 rounded-full bg-white/20" />
                <div className="w-2.5 h-2.5 rounded-full bg-white/20" />
                <div className="w-2.5 h-2.5 rounded-full bg-white/20" />
              </div>
            </div>

            {/* Current site */}
            <div className="px-4 pt-3 pb-2 border-b border-[var(--border)]">
              <div className="text-[10px] font-mono uppercase tracking-widest text-[var(--muted-foreground)] mb-1">
                Current Site
              </div>
              <div className="flex items-center gap-2">
                <div className="w-3.5 h-3.5 rounded-sm bg-blue-100 flex items-center justify-center">
                  <span className="text-[8px] text-blue-600 font-bold">G</span>
                </div>
                <span className="text-xs font-mono text-[var(--foreground)] truncate">{demo.url}</span>
              </div>
            </div>

            {/* Body */}
            <div className="p-4">
              {state === "idle" && (
                <div className="text-center py-4">
                  <div className="w-10 h-10 rounded-xl bg-[var(--secondary)] flex items-center justify-center mx-auto mb-3">
                    <svg className="w-5 h-5 text-[var(--primary)]" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="1.8">
                      <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                    </svg>
                  </div>
                  <p className="text-sm font-medium text-[var(--foreground)] mb-0.5">Site not scanned yet</p>
                  <p className="text-xs text-[var(--muted-foreground)] mb-4">Click scan to check this page.</p>
                  <button
                    onClick={scan}
                    className="w-full bg-[var(--primary)] hover:bg-blue-700 text-white font-display font-600 text-sm rounded-xl py-2.5 transition-all"
                  >
                    Scan This Site
                  </button>
                </div>
              )}

              {state === "scanning" && (
                <div className="text-center py-4">
                  <div className="relative w-10 h-10 mx-auto mb-3">
                    <div className="absolute inset-0 rounded-full border-2 border-[var(--border)]" />
                    <svg className="absolute inset-0 animate-spin-slow" width="40" height="40" viewBox="0 0 40 40">
                      <circle cx="20" cy="20" r="17" fill="none" stroke="#1a56db" strokeWidth="2" strokeLinecap="round" strokeDasharray="28 80" />
                    </svg>
                  </div>
                  <p className="text-sm font-medium text-[var(--foreground)]">Analyzing…</p>
                  <div className="mt-3 space-y-1.5">
                    {["URL Structure", "Domain", "Reputation"].map((c) => (
                      <div key={c} className="flex items-center gap-2 text-xs text-[var(--muted-foreground)]">
                        <span className="w-1.5 h-1.5 rounded-full bg-blue-400 animate-pulse" />
                        {c}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {state === "done" && (
                <div>
                  <div className={`rounded-xl p-3 mb-3 ${verdictColors[demo.verdict].bg}`}>
                    <div className="flex items-center justify-between mb-2">
                      <VerdictBadge verdict={demo.verdict} size="sm" />
                      <RiskMeter score={demo.score} verdict={demo.verdict} size="sm" />
                    </div>
                    <p className="text-xs text-[var(--foreground)] leading-relaxed">{demo.summary}</p>
                  </div>

                  {/* Mini score bar */}
                  <div className="mb-3">
                    <div className="flex justify-between text-[10px] font-mono text-[var(--muted-foreground)] mb-1">
                      <span>Risk Level</span>
                      <span>{demo.score}/100</span>
                    </div>
                    <div className="h-1.5 bg-[var(--muted)] rounded-full overflow-hidden">
                      <div
                        className={`h-full rounded-full transition-all duration-700 ${verdictColors[demo.verdict].bar}`}
                        style={{ width: `${demo.score}%` }}
                      />
                    </div>
                  </div>

                  <button
                    onClick={onViewReport}
                    className="w-full bg-[var(--primary)] hover:bg-blue-700 text-white font-display font-600 text-xs rounded-xl py-2.5 transition-all mb-2"
                  >
                    View Full Report →
                  </button>
                  <button
                    onClick={reset}
                    className="w-full text-xs text-[var(--muted-foreground)] hover:text-[var(--foreground)] py-1 transition-colors"
                  >
                    Reset
                  </button>
                </div>
              )}
            </div>
          </div>

          {/* Controls */}
          <div className="flex-1 w-full">
            <h2 className="font-display font-600 text-base text-[var(--foreground)] mb-3">
              Demo Scenarios
            </h2>
            <div className="flex flex-col gap-2.5">
              {DEMO_SITES.map((site, i) => (
                <button
                  key={i}
                  onClick={() => { setDemoIdx(i); setState("idle"); }}
                  className={`text-left rounded-2xl border p-4 transition-all ${
                    demoIdx === i
                      ? "border-[var(--primary)] bg-[var(--secondary)]"
                      : "border-[var(--border)] bg-white hover:border-blue-200"
                  }`}
                >
                  <div className="flex items-center gap-2 mb-1">
                    <VerdictBadge verdict={site.verdict} size="sm" />
                    <span className="font-mono text-xs text-[var(--muted-foreground)]">
                      Score: {site.score}/100
                    </span>
                  </div>
                  <p className="font-mono text-xs text-[var(--foreground)] break-all">{site.url}</p>
                </button>
              ))}
            </div>

            <div className="mt-6 bg-[var(--muted)] rounded-2xl p-4">
              <p className="text-xs font-mono font-600 uppercase tracking-widest text-[var(--muted-foreground)] mb-2">
                About the Extension
              </p>
              <p className="text-sm text-[var(--foreground)] leading-relaxed">
                The PhishGuard browser extension checks every page you visit in real time, alerting you before you interact with a suspicious site. Available for Chrome, Edge, and Firefox.
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
