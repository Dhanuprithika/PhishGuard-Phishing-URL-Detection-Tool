import { useState } from "react";
import type { ScanResult } from "../types";
import RiskMeter from "../components/RiskMeter";
import VerdictBadge from "../components/VerdictBadge";
import CheckList from "../components/CheckList";

interface ResultScreenProps {
  result: ScanResult;
  onScanAnother: () => void;
  onViewAnalysis: () => void;
}

const verdictConfig = {
  safe: {
    bannerBg: "bg-green-50 border-green-200",
    headline: "This URL appears safe.",
    icon: (
      <svg className="w-6 h-6 text-green-600" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
        <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
      </svg>
    ),
  },
  suspicious: {
    bannerBg: "bg-orange-50 border-orange-200",
    headline: "Proceed with caution.",
    icon: (
      <svg className="w-6 h-6 text-orange-600" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
        <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
      </svg>
    ),
  },
  phishing: {
    bannerBg: "bg-red-50 border-red-200",
    headline: "Do not enter sensitive information.",
    icon: (
      <svg className="w-6 h-6 text-red-600" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
        <path strokeLinecap="round" strokeLinejoin="round" d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636" />
      </svg>
    ),
  },
};

const flagReasons: Record<string, string> = {
  "No HTTPS encryption": "The URL uses plain HTTP, meaning any data transmitted is unencrypted and can be intercepted by third parties.",
  "Suspicious keywords in URL path": "Words like \"login\", \"verify\", \"secure\", or \"account\" in the path are commonly used by phishing pages to mimic legitimate services.",
  "Excessive subdomain depth": "Phishing URLs often use long subdomain chains (e.g. paypal.secure.login.malicious.com) to visually bury the real domain.",
  "IP address used as hostname": "Legitimate services use domain names, not raw IP addresses. Using an IP as a hostname is a strong indicator of malicious intent.",
  "Encoded/obfuscated URL components": "Base64-encoded or percent-encoded segments in the URL are used to hide destination content from security scanners.",
  "Abnormal query parameter count": "An unusually large number of query parameters can indicate tracking, fingerprinting, or an attempt to confuse automated scanners.",
  "Matches known phishing patterns": "The URL structure matches signatures found in known phishing campaigns in our threat intelligence database.",
  "Domain registered recently": "Domains registered in the last 30 days are statistically far more likely to be used for phishing or spam.",
};

export default function ResultScreen({ result, onScanAnother, onViewAnalysis }: ResultScreenProps) {
  const [showFlagged, setShowFlagged] = useState(false);
  const vc = verdictConfig[result.verdict];
  const truncated = result.url.length > 70 ? result.url.slice(0, 70) + "…" : result.url;
  const showFlagSection = result.verdict !== "safe" && result.indicators.length > 0;

  return (
    <div className="min-h-screen py-10 px-4">
      <div className="max-w-2xl mx-auto animate-fade-up">
        {/* URL reference */}
        <div className="mb-6 flex items-center gap-2 text-xs text-[var(--muted-foreground)] font-mono bg-white border border-[var(--border)] rounded-xl px-4 py-2.5 shadow-sm">
          <svg className="w-3.5 h-3.5 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
            <path strokeLinecap="round" strokeLinejoin="round" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1" />
          </svg>
          <span className="truncate">{truncated}</span>
        </div>

        {/* Main card */}
        <div className="bg-white rounded-2xl border border-[var(--border)] shadow-sm overflow-hidden mb-4">
          {/* Verdict banner */}
          <div className={`border-b px-6 py-5 flex flex-col sm:flex-row sm:items-center gap-4 ${vc.bannerBg}`}>
            <div className="flex items-center gap-3 flex-1">
              <div className="p-2 bg-white rounded-xl shadow-sm">{vc.icon}</div>
              <div>
                <VerdictBadge verdict={result.verdict} size="md" />
                <p className="text-sm font-medium text-[var(--foreground)] mt-1">{vc.headline}</p>
              </div>
            </div>
            <div className="self-center sm:self-auto">
              <RiskMeter score={result.riskScore} verdict={result.verdict} size="md" />
            </div>
          </div>

          {/* Explanation */}
          <div className="px-6 py-5 border-b border-[var(--border)]">
            <h3 className="text-xs font-mono font-600 uppercase tracking-widest text-[var(--muted-foreground)] mb-2">
              Analysis Summary
            </h3>
            <p className="text-sm text-[var(--foreground)] leading-relaxed">{result.explanation}</p>
          </div>

          {/* Security checks */}
          <div className="px-6 py-5 border-b border-[var(--border)]">
            <h3 className="text-xs font-mono font-600 uppercase tracking-widest text-[var(--muted-foreground)] mb-3">
              Security Checks
            </h3>
            <CheckList checks={result.checks} />
          </div>

          {/* Why flagged? — expandable for suspicious/phishing */}
          {showFlagSection && (
            <div className="border-b border-[var(--border)]">
              <button
                onClick={() => setShowFlagged((v) => !v)}
                className="w-full px-6 py-4 flex items-center justify-between text-left hover:bg-[var(--muted)] transition-colors"
              >
                <h3 className="text-xs font-mono font-600 uppercase tracking-widest text-[var(--muted-foreground)]">
                  Why was this flagged?
                </h3>
                <svg
                  className={`w-4 h-4 text-[var(--muted-foreground)] transition-transform duration-200 ${showFlagged ? "rotate-180" : ""}`}
                  fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2"
                >
                  <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
                </svg>
              </button>
              {showFlagged && (
                <div className="px-6 pb-5 flex flex-col gap-3">
                  {result.indicators.map((ind, i) => {
                    const explanation = flagReasons[ind];
                    return (
                      <div
                        key={i}
                        className={`rounded-xl border p-3.5 ${
                          result.verdict === "phishing"
                            ? "bg-red-50 border-red-200"
                            : "bg-orange-50 border-orange-200"
                        }`}
                      >
                        <div className="flex items-start gap-2.5">
                          <span className={`text-sm font-600 flex-shrink-0 mt-0.5 ${result.verdict === "phishing" ? "text-red-600" : "text-orange-600"}`}>
                            ▲
                          </span>
                          <div>
                            <p className={`text-sm font-medium mb-1 ${result.verdict === "phishing" ? "text-red-800" : "text-orange-800"}`}>
                              {ind}
                            </p>
                            {explanation && (
                              <p className="text-xs text-[var(--muted-foreground)] leading-relaxed">{explanation}</p>
                            )}
                          </div>
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          )}

          {/* Recommendation */}
          <div className="px-6 py-5">
            <h3 className="text-xs font-mono font-600 uppercase tracking-widest text-[var(--muted-foreground)] mb-2">
              Recommendation
            </h3>
            <p className="text-sm text-[var(--foreground)] leading-relaxed">{result.recommendation}</p>
          </div>
        </div>

        {/* Actions */}
        <div className="flex flex-col sm:flex-row gap-3">
          <button
            onClick={onScanAnother}
            className="flex-1 bg-white border border-[var(--border)] hover:border-[var(--primary)] text-[var(--foreground)] hover:text-[var(--primary)] font-medium text-sm rounded-xl py-3 transition-all duration-150"
          >
            Scan Another URL
          </button>
          <button
            onClick={onViewAnalysis}
            className="flex-1 bg-[var(--primary)] hover:bg-blue-700 text-white font-display font-600 text-sm rounded-xl py-3 transition-all duration-150 shadow-sm hover:shadow-md hover:shadow-blue-200"
          >
            View Full Analysis →
          </button>
        </div>
      </div>
    </div>
  );
}
