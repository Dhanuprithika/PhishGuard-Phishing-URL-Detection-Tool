export type Verdict = "safe" | "suspicious" | "phishing";

export interface CheckItem {
  label: string;
  status: "pass" | "warn" | "fail" | "scanning";
  detail?: string;
}

export interface ScanResult {
  url: string;
  verdict: Verdict;
  riskScore: number;
  checks: CheckItem[];
  indicators: string[];
  explanation: string;
  recommendation: string;
  domain: string;
  https: boolean;
  ipReputation: "clean" | "flagged" | "unknown";
  subdomains: number;
  blacklisted: boolean;
  registrationAge: string;
  scannedAt: Date;
}

export type AppScreen =
  | "home"
  | "scanning"
  | "result"
  | "analysis"
  | "history"
  | "extension";
