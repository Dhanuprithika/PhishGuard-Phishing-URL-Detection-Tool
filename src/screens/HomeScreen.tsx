import { useState } from "react";
import ShieldLogo from "../components/ShieldLogo";

interface HomeScreenProps {
  onScan: (url: string) => void;
}

export default function HomeScreen({ onScan }: HomeScreenProps) {
  const [url, setUrl] = useState("");
  const [error, setError] = useState("");

  function validateAndScan() {
    const trimmed = url.trim();
    if (!trimmed) {
      setError("Please paste a URL to scan.");
      return;
    }
    const normalized =
      trimmed.startsWith("http://") || trimmed.startsWith("https://")
        ? trimmed
        : "https://" + trimmed;
    try {
      new URL(normalized);
      setError("");
      onScan(normalized);
    } catch {
      setError("That doesn't look like a valid URL. Try including the full address.");
    }
  }

  function handleKey(e: React.KeyboardEvent) {
    if (e.key === "Enter") validateAndScan();
  }

  const features = [
    {
      icon: (
        <svg width="20" height="20" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="1.8">
          <path strokeLinecap="round" strokeLinejoin="round" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1" />
        </svg>
      ),
      title: "URL Intelligence",
      desc: "Deep structural analysis of domains, subdomains, paths, and query parameters to detect deceptive patterns.",
    },
    {
      icon: (
        <svg width="20" height="20" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="1.8">
          <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
        </svg>
      ),
      title: "Threat Detection",
      desc: "Cross-referenced against live threat intelligence feeds, blacklists, and known phishing campaign signatures.",
    },
    {
      icon: (
        <svg width="20" height="20" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="1.8">
          <path strokeLinecap="round" strokeLinejoin="round" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
        </svg>
      ),
      title: "Explainable Results",
      desc: "Every risk score comes with a plain-language breakdown — not just a verdict, but the reasoning behind it.",
    },
  ];

  return (
    <div className="min-h-screen flex flex-col">
      {/* Hero */}
      <section className="flex-1 flex flex-col items-center justify-center px-4 pt-16 pb-12">
        <div className="flex flex-col items-center text-center max-w-xl w-full animate-fade-up">
          <div className="mb-6 relative">
            <div className="absolute inset-0 rounded-full bg-blue-100 scale-150 opacity-40 animate-pulse-ring" />
            <ShieldLogo size={56} />
          </div>

          <h1 className="font-display font-800 text-4xl sm:text-5xl text-[var(--foreground)] tracking-tight leading-tight mb-4">
            Know Before<br />
            <span className="text-[var(--primary)]">You Click.</span>
          </h1>

          <p className="text-base text-[var(--muted-foreground)] max-w-sm mb-10 leading-relaxed">
            Instantly analyze any URL for phishing, malware, and deceptive patterns — before you open it.
          </p>

          {/* Scanner Input */}
          <div className="w-full max-w-lg">
            <div
              className={`flex items-center gap-2 bg-white rounded-2xl border-2 transition-all duration-200 px-4 py-3 shadow-sm ${
                error
                  ? "border-red-300 shadow-red-100"
                  : "border-[var(--border)] focus-within:border-[var(--primary)] focus-within:shadow-blue-100 focus-within:shadow-md"
              }`}
            >
              <svg className="w-5 h-5 text-[var(--muted-foreground)] flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
                <path strokeLinecap="round" strokeLinejoin="round" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1" />
              </svg>
              <input
                type="url"
                value={url}
                onChange={(e) => { setUrl(e.target.value); setError(""); }}
                onKeyDown={handleKey}
                placeholder="Paste a URL to check its safety…"
                className="flex-1 bg-transparent text-sm text-[var(--foreground)] placeholder:text-[var(--muted-foreground)] outline-none min-w-0 font-mono"
                autoFocus
              />
              {url && (
                <button
                  onClick={() => { setUrl(""); setError(""); }}
                  className="text-[var(--muted-foreground)] hover:text-[var(--foreground)] transition-colors p-0.5"
                >
                  ✕
                </button>
              )}
            </div>
            {error && (
              <p className="mt-2 text-xs text-red-500 text-left px-1">{error}</p>
            )}

            <button
              onClick={validateAndScan}
              className="mt-3 w-full bg-[var(--primary)] hover:bg-blue-700 text-white font-display font-600 text-sm rounded-xl py-3 transition-all duration-150 active:scale-[0.98] shadow-sm hover:shadow-md hover:shadow-blue-200"
            >
              Scan URL
            </button>

            <p className="mt-3 text-xs text-[var(--muted-foreground)] text-center">
              We analyze the URL without opening the destination.
            </p>
          </div>

          {/* Quick examples */}
          <div className="mt-6 flex flex-wrap justify-center gap-2">
            {[
              "https://github.com/anthropics",
              "http://paypa1-verify.tk/login",
              "https://dropbox-share.files.net/doc",
            ].map((ex) => (
              <button
                key={ex}
                onClick={() => { setUrl(ex); setError(""); }}
                className="text-xs text-[var(--muted-foreground)] hover:text-[var(--primary)] bg-[var(--muted)] hover:bg-[var(--secondary)] rounded-lg px-3 py-1.5 transition-all font-mono"
              >
                {ex.length > 36 ? ex.slice(0, 36) + "…" : ex}
              </button>
            ))}
          </div>
        </div>
      </section>

      {/* Feature cards */}
      <section className="max-w-5xl mx-auto w-full px-4 sm:px-6 pb-16">
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
          {features.map((f, i) => (
            <div
              key={i}
              className="bg-white rounded-2xl border border-[var(--border)] p-5 shadow-sm hover:shadow-md hover:border-blue-200 transition-all duration-200 group"
            >
              <div className="w-10 h-10 rounded-xl bg-[var(--secondary)] text-[var(--primary)] flex items-center justify-center mb-3 group-hover:bg-blue-100 transition-colors">
                {f.icon}
              </div>
              <h3 className="font-display font-600 text-[var(--foreground)] mb-1.5">{f.title}</h3>
              <p className="text-sm text-[var(--muted-foreground)] leading-relaxed">{f.desc}</p>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}
