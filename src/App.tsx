import { useState, useCallback, useEffect } from "react";
import type { AppScreen, ScanResult } from "./types";
import { historyData } from "./mockData";
import { scanUrl } from "./services/api";

import Header from "./components/Header";
import HomeScreen from "./screens/HomeScreen";
import ScanningScreen from "./screens/ScanningScreen";
import ResultScreen from "./screens/ResultScreen";
import AnalysisScreen from "./screens/AnalysisScreen";
import HistoryScreen from "./screens/HistoryScreen";
import ExtensionScreen from "./screens/ExtensionScreen";
import Footer from "./components/Footer";

const STORAGE_KEY = "phishguard_scan_history_v1";

function loadHistory(): ScanResult[] {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return historyData;
    const parsed = JSON.parse(raw);
    return parsed.map((item: any) => ({
      ...item,
      scannedAt: new Date(item.scannedAt),
    }));
  } catch {
    return historyData;
  }
}

function saveHistory(list: ScanResult[]) {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(list));
  } catch (err) {
    console.error("Failed to save history to localStorage:", err);
  }
}

export default function App() {
  const [screen, setScreen] = useState<AppScreen>("home");
  const [scanUrlTarget, setScanUrlTarget] = useState("");
  const [result, setResult] = useState<ScanResult | null>(null);
  const [history, setHistory] = useState<ScanResult[]>(loadHistory);

  // Check URL query parameters (for browser extension "View Full Report" integration)
  useEffect(() => {
    try {
      const params = new URLSearchParams(window.location.search);
      const targetUrl = params.get("url") || params.get("scan");
      if (targetUrl) {
        startScan(targetUrl);
        // Clean URL without reload
        window.history.replaceState({}, document.title, window.location.pathname);
      }
    } catch {}
  }, []);

  function startScan(url: string) {
    setScanUrlTarget(url);
    setScreen("scanning");
  }

  const handleScanComplete = useCallback((scannedResult: ScanResult) => {
    setResult(scannedResult);
    setHistory((prev) => {
      // avoid duplicate url at top
      const deduped = prev.filter((h) => h.url !== scannedResult.url);
      const updated = [scannedResult, ...deduped];
      saveHistory(updated);
      return updated;
    });
    setScreen("result");
  }, []);

  function goHome() {
    setScreen("home");
    setScanUrlTarget("");
    setResult(null);
  }

  return (
    <div className="min-h-full bg-[var(--background)] flex flex-col">
      <Header
        screen={screen}
        onNavigate={(s) => {
          if (s === "home") goHome();
          else setScreen(s);
        }}
      />
      <main className="flex-1">
        {screen === "home" && (
          <HomeScreen onScan={startScan} />
        )}
        {screen === "scanning" && (
          <ScanningScreen url={scanUrlTarget} onComplete={handleScanComplete} />
        )}
        {screen === "result" && result && (
          <ResultScreen
            result={result}
            onScanAnother={goHome}
            onViewAnalysis={() => setScreen("analysis")}
          />
        )}
        {screen === "analysis" && result && (
          <AnalysisScreen
            result={result}
            onBack={() => setScreen("result")}
            onScanAnother={goHome}
          />
        )}
        {screen === "history" && (
          <HistoryScreen history={history} onRescan={startScan} />
        )}
        {screen === "extension" && (
          <ExtensionScreen
            onViewReport={async () => {
              const demoUrl = "https://dropbox-share.files.net";
              startScan(demoUrl);
            }}
          />
        )}
      </main>
      <Footer />
    </div>
  );
}
