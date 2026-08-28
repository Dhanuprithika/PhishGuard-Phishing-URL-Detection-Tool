import type { ScanResult } from "../types";
import { generateMockResult } from "../mockData";

const API_BASE_URL = (import.meta.env.VITE_API_URL as string) || "http://127.0.0.1:8000";

export async function scanUrl(url: string): Promise<ScanResult> {
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 8000);

    const response = await fetch(`${API_BASE_URL}/api/scan`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ url }),
      signal: controller.signal,
    });

    clearTimeout(timeoutId);

    if (!response.ok) {
      const err = await response.json().catch(() => ({}));
      throw new Error(err.detail || `Scan request failed: ${response.statusText}`);
    }

    const data = await response.json();

    return {
      url: data.url,
      verdict: data.verdict,
      riskScore: data.riskScore ?? data.risk_score,
      checks: data.checks || [],
      indicators: data.indicators || [],
      explanation: data.explanation || "",
      recommendation: data.recommendation || "",
      domain: data.domain,
      https: data.https,
      ipReputation: data.ipReputation || data.ip_reputation || "clean",
      subdomains: data.subdomains ?? 0,
      blacklisted: data.blacklisted ?? false,
      registrationAge: data.registrationAge || data.registration_age || "Unknown",
      scannedAt: data.scannedAt ? new Date(data.scannedAt) : new Date(),
    };
  } catch (error) {
    console.warn("Backend API unavailable or error occurred, using client heuristic engine:", error);
    // Fallback to local heuristic computation so the app never breaks
    return generateMockResult(url);
  }
}

export async function checkApiHealth(): Promise<boolean> {
  try {
    const res = await fetch(`${API_BASE_URL}/api/health`, { method: "GET" });
    return res.ok;
  } catch {
    return false;
  }
}
