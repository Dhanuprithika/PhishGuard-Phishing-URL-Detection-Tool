import { useEffect, useState, useRef } from "react";
import type { ScanResult } from "../types";
import { scanUrl } from "../services/api";

interface ScanningScreenProps {
  url: string;
  onComplete: (result: ScanResult) => void;
}

const CHECKS = [
  { label: "URL Structure", detail: "Parsing domain, path, and parameters…" },
  { label: "Domain Intelligence", detail: "Checking registration age and WHOIS data…" },
  { label: "Reputation Databases", detail: "Cross-referencing threat intelligence feeds…" },
  { label: "Threat Indicators", detail: "Scanning for known phishing patterns…" },
  { label: "Risk Assessment", detail: "Computing final risk score…" },
];

export default function ScanningScreen({ url, onComplete }: ScanningScreenProps) {
  const [completedCount, setCompletedCount] = useState(0);
  const [currentDetail, setCurrentDetail] = useState(CHECKS[0].detail);
  const scanResultRef = useRef<ScanResult | null>(null);

  useEffect(() => {
    let isMounted = true;

    // Trigger real backend scan
    scanUrl(url)
      .then((res) => {
        if (isMounted) {
          scanResultRef.current = res;
        }
      })
      .catch((err) => {
        console.error("Scan error:", err);
      });

    const timers: ReturnType<typeof setTimeout>[] = [];
    CHECKS.forEach((check, i) => {
      timers.push(
        setTimeout(() => {
          if (isMounted) {
            setCompletedCount(i + 1);
            setCurrentDetail(CHECKS[Math.min(i + 1, CHECKS.length - 1)].detail);
          }
        }, 400 + i * 320)
      );
    });

    // Complete scan after minimum visual animation steps
    const minTime = 400 + CHECKS.length * 320 + 200;
    timers.push(
      setTimeout(async () => {
        if (!isMounted) return;
        if (scanResultRef.current) {
          onComplete(scanResultRef.current);
        } else {
          // If network is still pending, wait briefly or fallback
          const finalResult = await scanUrl(url);
          if (isMounted) {
            onComplete(finalResult);
          }
        }
      }, minTime)
    );

    return () => {
      isMounted = false;
      timers.forEach(clearTimeout);
    };
  }, [url, onComplete]);

  const truncated = url.length > 60 ? url.slice(0, 60) + "…" : url;

  return (
    <div className="min-h-screen flex items-center justify-center px-4 py-16">
      <div className="w-full max-w-md">
        {/* Spinner */}
        <div className="flex justify-center mb-8">
          <div className="relative w-20 h-20">
            <div className="absolute inset-0 rounded-full border-4 border-[var(--border)]" />
            <svg
              className="absolute inset-0 animate-spin-slow"
              width="80"
              height="80"
              viewBox="0 0 80 80"
            >
              <circle
                cx="40"
                cy="40"
                r="36"
                fill="none"
                stroke="url(#scan-grad)"
                strokeWidth="4"
                strokeLinecap="round"
                strokeDasharray="56 170"
              />
              <defs>
                <linearGradient id="scan-grad" x1="0%" y1="0%" x2="100%" y2="0%">
                  <stop offset="0%" stopColor="#1a56db" stopOpacity="0" />
                  <stop offset="100%" stopColor="#1a56db" />
                </linearGradient>
              </defs>
            </svg>
            <div className="absolute inset-0 flex items-center justify-center">
              <svg width="28" height="28" fill="none" viewBox="0 0 24 24" stroke="#1a56db" strokeWidth="1.8">
                <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
              </svg>
            </div>
          </div>
        </div>

        <div className="text-center mb-8">
          <h2 className="font-display font-700 text-2xl text-[var(--foreground)] mb-2">
            Analyzing URL…
          </h2>
          <p className="font-mono text-xs text-[var(--muted-foreground)] bg-[var(--muted)] rounded-lg px-3 py-2 inline-block break-all">
            {truncated}
          </p>
          <p className="text-sm text-[var(--muted-foreground)] mt-3 h-5 transition-all">
            {currentDetail}
          </p>
        </div>

        {/* Progress checks */}
        <div className="bg-white rounded-2xl border border-[var(--border)] p-4 shadow-sm">
          <div className="flex flex-col gap-2">
            {CHECKS.map((check, i) => {
              const done = i < completedCount;
              const active = i === completedCount;
              return (
                <div
                  key={i}
                  className={`flex items-center gap-3 py-2 px-3 rounded-xl transition-all duration-300 ${
                    done ? "bg-green-50" : active ? "bg-blue-50" : ""
                  }`}
                >
                  <div className="w-5 h-5 flex-shrink-0 flex items-center justify-center">
                    {done ? (
                      <span className="w-5 h-5 rounded-full bg-green-100 flex items-center justify-center text-green-600 text-xs font-bold">
                        ✓
                      </span>
                    ) : active ? (
                      <span className="w-3 h-3 rounded-full bg-blue-400 animate-pulse" />
                    ) : (
                      <span className="w-3 h-3 rounded-full bg-[var(--border)]" />
                    )}
                  </div>
                  <span
                    className={`text-sm font-medium transition-colors ${
                      done
                        ? "text-green-700"
                        : active
                          ? "text-[var(--primary)]"
                          : "text-[var(--muted-foreground)]"
                    }`}
                  >
                    {check.label}
                  </span>
                </div>
              );
            })}
          </div>

          <div className="mt-4 bg-[var(--muted)] rounded-full h-1.5 overflow-hidden">
            <div
              className="h-full bg-[var(--primary)] rounded-full transition-all duration-500 ease-out"
              style={{ width: `${(completedCount / CHECKS.length) * 100}%` }}
            />
          </div>
        </div>
      </div>
    </div>
  );
}
