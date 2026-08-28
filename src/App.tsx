import { useState, useCallback } from "react";
import type { AppScreen, ScanResult } from "./types";
import { generateMockResult, historyData } from "./mockData";

import Header from "./components/Header";
import HomeScreen from "./screens/HomeScreen";
import ScanningScreen from "./screens/ScanningScreen";
import ResultScreen from "./screens/ResultScreen";
import AnalysisScreen from "./screens/AnalysisScreen";
import HistoryScreen from "./screens/HistoryScreen";
import ExtensionScreen from "./screens/ExtensionScreen";
import Footer from "./components/Footer";

export default function App() {
  const [screen, setScreen] = useState<AppScreen>("home");
  const [scanUrl, setScanUrl] = useState("");
  const [result, setResult] = useState<ScanResult | null>(null);
  const [history, setHistory] = useState<ScanResult[]>(historyData);

  function startScan(url: string) {
    setScanUrl(url);
    setScreen("scanning");
  }

  const handleScanComplete = useCallback(() => {
    const r = generateMockResult(scanUrl);
    setResult(r);
    setHistory((prev) => {
      // avoid duplicates for same URL scanned in same session
      const deduped = prev.filter((h) => h.url !== r.url);
      return [r, ...deduped];
    });
    setScreen("result");
  }, [scanUrl]);

  function goHome() {
    setScreen("home");
    setScanUrl("");
    setResult(null);
  }

  return (
    <div className="min-h-full bg-[var(--background)] flex flex-col">
      <Header screen={screen} onNavigate={(s) => {
        if (s === "home") goHome();
        else setScreen(s);
      }} />
      <main className="flex-1">
        {screen === "home" && (
          <HomeScreen onScan={startScan} />
        )}
        {screen === "scanning" && (
          <ScanningScreen url={scanUrl} onComplete={handleScanComplete} />
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
          <ExtensionScreen onViewReport={() => {
            const r = generateMockResult("https://demo.phishguard.io");
            setResult(r);
            setScreen("result");
          }} />
        )}
      </main>
      <Footer />
    </div>
  );
}
