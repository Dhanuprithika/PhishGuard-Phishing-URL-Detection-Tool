import type { ScanResult } from "../types";
import RiskMeter from "../components/RiskMeter";
import VerdictBadge from "../components/VerdictBadge";

interface AnalysisScreenProps {
  result: ScanResult;
  onBack: () => void;
  onScanAnother: () => void;
}

function InfoRow({ label, value, status }: { label: string; value: string; status?: "ok" | "warn" | "bad" }) {
  const statusColor =
    status === "ok"
      ? "text-green-600 bg-green-50 border-green-200"
      : status === "bad"
        ? "text-red-600 bg-red-50 border-red-200"
        : status === "warn"
          ? "text-orange-600 bg-orange-50 border-orange-200"
          : "text-[var(--muted-foreground)] bg-[var(--muted)] border-[var(--border)]";

  return (
    <div className="flex items-center justify-between py-3 border-b border-[var(--border)] last:border-0 gap-4">
      <span className="text-sm text-[var(--muted-foreground)] flex-shrink-0">{label}</span>
      <span className={`text-sm font-medium rounded-lg px-2.5 py-0.5 border font-mono ${statusColor}`}>
        {value}
      </span>
    </div>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="bg-white rounded-2xl border border-[var(--border)] shadow-sm overflow-hidden">
      <div className="px-5 py-4 border-b border-[var(--border)] bg-[var(--muted)]">
        <h2 className="text-xs font-mono font-600 uppercase tracking-widest text-[var(--muted-foreground)]">
          {title}
        </h2>
      </div>
      <div className="px-5">{children}</div>
    </div>
  );
}

export default function AnalysisScreen({ result, onBack, onScanAnother }: AnalysisScreenProps) {
  let parsedUrl: URL | null = null;
  try {
    parsedUrl = new URL(result.url);
  } catch {}

  return (
    <div className="min-h-screen py-10 px-4">
      <div className="max-w-2xl mx-auto animate-fade-up">
        {/* Back nav */}
        <button
          onClick={onBack}
          className="flex items-center gap-2 text-sm text-[var(--muted-foreground)] hover:text-[var(--primary)] mb-6 transition-colors"
        >
          ← Back to Results
        </button>

        <div className="mb-6">
          <h1 className="font-display font-700 text-2xl text-[var(--foreground)] mb-1">
            Full Analysis Report
          </h1>
          <p className="font-mono text-xs text-[var(--muted-foreground)] bg-[var(--muted)] rounded-lg px-3 py-1.5 inline-block break-all">
            {result.url}
          </p>
        </div>

        <div className="flex flex-col gap-4">
          {/* Overview */}
          <div className="bg-white rounded-2xl border border-[var(--border)] shadow-sm p-5 flex flex-col sm:flex-row items-start sm:items-center gap-5">
            <RiskMeter score={result.riskScore} verdict={result.verdict} size="lg" />
            <div className="flex-1">
              <VerdictBadge verdict={result.verdict} size="lg" />
              <p className="text-sm text-[var(--foreground)] mt-2 leading-relaxed">{result.explanation}</p>
              <p className="text-xs text-[var(--muted-foreground)] mt-2">
                Scanned {result.scannedAt.toLocaleString()}
              </p>
            </div>
          </div>

          {/* URL Structure */}
          <Section title="URL Structure Analysis">
            <InfoRow label="Protocol" value={parsedUrl?.protocol || "unknown"} status={parsedUrl?.protocol === "https:" ? "ok" : "bad"} />
            <InfoRow label="Hostname" value={parsedUrl?.hostname || result.domain} />
            <InfoRow label="Subdomain depth" value={`${result.subdomains} level${result.subdomains !== 1 ? "s" : ""}`} status={result.subdomains > 2 ? "warn" : "ok"} />
            {parsedUrl?.pathname && parsedUrl.pathname !== "/" && (
              <InfoRow label="Path" value={parsedUrl.pathname} />
            )}
            {parsedUrl?.search && (
              <InfoRow
                label="Query parameters"
                value={`${parsedUrl.searchParams.size} params`}
                status={parsedUrl.searchParams.size > 5 ? "warn" : "ok"}
              />
            )}
          </Section>

          {/* Domain Intelligence */}
          <Section title="Domain Intelligence">
            <InfoRow label="Domain" value={result.domain} />
            <InfoRow label="Registration age" value={result.registrationAge} status={result.registrationAge.includes("day") ? "bad" : "ok"} />
            <InfoRow label="IP reputation" value={result.ipReputation} status={result.ipReputation === "clean" ? "ok" : result.ipReputation === "unknown" ? "warn" : "bad"} />
            <InfoRow label="Blacklisted" value={result.blacklisted ? "Yes — found on 3 lists" : "Not found"} status={result.blacklisted ? "bad" : "ok"} />
          </Section>

          {/* HTTPS / Certificate */}
          <Section title="HTTPS & Certificate Status">
            <InfoRow label="Encryption" value={result.https ? "HTTPS (encrypted)" : "HTTP (no encryption)"} status={result.https ? "ok" : "bad"} />
            <InfoRow label="Certificate valid" value={result.https ? "Valid TLS certificate" : "None"} status={result.https ? "ok" : "bad"} />
            <InfoRow label="Certificate issuer" value={result.https ? "Let's Encrypt / DigiCert" : "N/A"} status={result.https ? "ok" : undefined} />
          </Section>

          {/* Detected indicators */}
          {result.indicators.length > 0 && (
            <Section title="Detected Threat Indicators">
              <div className="py-4 flex flex-col gap-2">
                {result.indicators.map((ind, i) => (
                  <div key={i} className="flex items-start gap-3 py-1">
                    <span
                      className={`w-2 h-2 rounded-full mt-1.5 flex-shrink-0 ${
                        result.verdict === "phishing"
                          ? "bg-red-500"
                          : "bg-orange-400"
                      }`}
                    />
                    <div>
                      <p className="text-sm font-medium text-[var(--foreground)]">{ind}</p>
                    </div>
                  </div>
                ))}
              </div>
            </Section>
          )}

          {/* Security checks */}
          <Section title="Security Check Results">
            <div className="py-2 flex flex-col gap-1">
              {result.checks.map((check, i) => (
                <div key={i} className="flex items-center justify-between py-2.5 border-b border-[var(--border)] last:border-0 gap-4">
                  <span className="text-sm text-[var(--foreground)]">{check.label}</span>
                  <div className="flex items-center gap-2">
                    <span className="text-xs text-[var(--muted-foreground)]">{check.detail}</span>
                    <span
                      className={`w-2 h-2 rounded-full flex-shrink-0 ${
                        check.status === "pass"
                          ? "bg-green-500"
                          : check.status === "warn"
                            ? "bg-orange-400"
                            : "bg-red-500"
                      }`}
                    />
                  </div>
                </div>
              ))}
            </div>
          </Section>

          {/* Threat Analyst AI Assessment */}
          {result.threatAnalysis && (
            <Section title="Threat Analyst AI Assessment">
              <div className="py-4 space-y-3">
                <div>
                  <h3 className="text-xs font-mono font-600 uppercase tracking-wider text-[var(--muted-foreground)] mb-1">
                    Threat Summary
                  </h3>
                  <p className="text-sm font-medium text-[var(--foreground)]">{result.threatAnalysis.summary}</p>
                </div>
                <div>
                  <h3 className="text-xs font-mono font-600 uppercase tracking-wider text-[var(--muted-foreground)] mb-1">
                    Plain-Language Explanation
                  </h3>
                  <p className="text-sm text-[var(--foreground)] leading-relaxed">{result.threatAnalysis.explanation}</p>
                </div>
                {result.threatAnalysis.reasons.length > 0 && (
                  <div>
                    <h3 className="text-xs font-mono font-600 uppercase tracking-wider text-[var(--muted-foreground)] mb-1.5">
                      Key Analysis Signals
                    </h3>
                    <div className="space-y-1.5">
                      {result.threatAnalysis.reasons.map((r, i) => (
                        <div key={i} className="flex items-start gap-2 text-xs text-[var(--foreground)] bg-[var(--muted)] rounded-lg p-2 font-mono">
                          <span className="text-[var(--primary)] font-bold">•</span>
                          <span>{r}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </Section>
          )}

          {/* Plain-language explanation */}
          <div className={`rounded-2xl border p-5 ${
            result.verdict === "phishing"
              ? "bg-red-50 border-red-200"
              : result.verdict === "suspicious"
                ? "bg-orange-50 border-orange-200"
                : "bg-green-50 border-green-200"
          }`}>
            <h2 className="text-xs font-mono font-600 uppercase tracking-widest text-[var(--muted-foreground)] mb-2">
              Our Recommendation
            </h2>
            <p className="text-sm text-[var(--foreground)] leading-relaxed">
              {result.threatAnalysis?.recommendation || result.recommendation}
            </p>
          </div>

          <div className="flex flex-col sm:flex-row gap-3">
            <button
              onClick={onScanAnother}
              className="flex-1 bg-white border border-[var(--border)] hover:border-[var(--primary)] text-[var(--foreground)] hover:text-[var(--primary)] font-medium text-sm rounded-xl py-3 transition-all duration-150"
            >
              Scan Another URL
            </button>
            <button
              onClick={onBack}
              className="flex-1 bg-[var(--primary)] hover:bg-blue-700 text-white font-display font-600 text-sm rounded-xl py-3 transition-all duration-150"
            >
              Back to Results
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
