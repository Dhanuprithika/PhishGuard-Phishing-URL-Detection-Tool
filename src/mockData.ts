import type { ScanResult } from "./types";

export function generateMockResult(url: string): ScanResult {
  const lower = url.toLowerCase();
  const hasHttp = lower.startsWith("http://");
  const hasSuspiciousKeywords = /paypal|login|verify|account|secure|update|bank|password|signin|credential/.test(lower);
  const hasLongSubdomains = (lower.match(/\./g) || []).length > 3;
  const hasIPAddress = /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(lower);
  const hasBase64 = lower.includes("base64") || lower.includes("%3d%3d");
  const hasExcessiveParams = (lower.match(/[&?]/g) || []).length > 5;

  let riskScore = 5;
  if (hasHttp) riskScore += 15;
  if (hasSuspiciousKeywords) riskScore += 28;
  if (hasLongSubdomains) riskScore += 18;
  if (hasIPAddress) riskScore += 30;
  if (hasBase64) riskScore += 20;
  if (hasExcessiveParams) riskScore += 10;
  riskScore += Math.floor(Math.random() * 8);
  riskScore = Math.min(97, riskScore);

  const verdict =
    riskScore >= 75 ? "phishing" : riskScore >= 45 ? "suspicious" : "safe";

  const domainMatch = url.match(/(?:https?:\/\/)?([^/?\s]+)/);
  const domain = domainMatch ? domainMatch[1] : url;
  const subdomains = (domain.match(/\./g) || []).length;

  const indicators: string[] = [];
  if (hasHttp) indicators.push("No HTTPS encryption");
  if (hasSuspiciousKeywords) indicators.push("Suspicious keywords in URL path");
  if (hasLongSubdomains) indicators.push("Excessive subdomain depth");
  if (hasIPAddress) indicators.push("IP address used as hostname");
  if (hasBase64) indicators.push("Encoded/obfuscated URL components");
  if (hasExcessiveParams) indicators.push("Abnormal query parameter count");
  if (verdict === "phishing") indicators.push("Matches known phishing patterns");
  if (verdict !== "safe") indicators.push("Domain registered recently");

  const explanations: Record<string, string> = {
    safe: "This URL appears legitimate. The domain has a clean reputation, uses HTTPS, and shows no signs of phishing or malicious behavior based on our analysis.",
    suspicious: "This URL has characteristics commonly associated with phishing or spam. While not definitively malicious, we recommend caution before proceeding.",
    phishing: "This URL exhibits multiple high-risk indicators consistent with known phishing campaigns. Do not interact with this site or enter any personal information.",
  };

  const recommendations: Record<string, string> = {
    safe: "You can proceed, but always stay vigilant. Avoid entering sensitive information unless you trust the destination.",
    suspicious: "Proceed with caution. Avoid entering passwords, credit card numbers, or personal data. Verify the site through official channels.",
    phishing: "Do not visit this URL. If you received this link via email or message, report it as phishing. Do not enter any personal or financial information.",
  };

  const checks = [
    {
      label: "URL Structure",
      status: hasIPAddress || hasBase64 ? "fail" : hasLongSubdomains ? "warn" : "pass",
      detail: hasIPAddress
        ? "IP address used instead of domain name"
        : hasLongSubdomains
          ? "Unusually deep subdomain structure"
          : "URL structure looks normal",
    },
    {
      label: "Domain Age & Registration",
      status: verdict === "phishing" ? "fail" : verdict === "suspicious" ? "warn" : "pass",
      detail: verdict === "safe" ? "Domain registered 4+ years ago" : "Domain registered within last 30 days",
    },
    {
      label: "HTTPS / Certificate",
      status: hasHttp ? "fail" : "pass",
      detail: hasHttp ? "Connection is unencrypted (HTTP only)" : "Valid TLS certificate detected",
    },
    {
      label: "Reputation & Blacklists",
      status: verdict === "phishing" ? "fail" : verdict === "suspicious" ? "warn" : "pass",
      detail: verdict === "phishing" ? "Found on 3 threat intelligence blacklists" : verdict === "suspicious" ? "1 low-confidence flag detected" : "No blacklist entries found",
    },
    {
      label: "Threat Indicators",
      status: indicators.length === 0 ? "pass" : indicators.length <= 2 ? "warn" : "fail",
      detail: `${indicators.length} indicator${indicators.length !== 1 ? "s" : ""} detected`,
    },
  ] as ScanResult["checks"];

  return {
    url,
    verdict,
    riskScore,
    checks,
    indicators,
    explanation: explanations[verdict],
    recommendation: recommendations[verdict],
    domain,
    https: !hasHttp,
    ipReputation: verdict === "phishing" ? "flagged" : "clean",
    subdomains,
    blacklisted: verdict === "phishing",
    registrationAge: verdict === "safe" ? "4 years, 7 months" : "23 days",
    scannedAt: new Date(),
  };
}

export const historyData: ScanResult[] = [
  {
    url: "https://github.com/anthropics/claude",
    verdict: "safe",
    riskScore: 4,
    checks: [],
    indicators: [],
    explanation: "Clean domain with long history and strong reputation.",
    recommendation: "Safe to proceed.",
    domain: "github.com",
    https: true,
    ipReputation: "clean",
    subdomains: 0,
    blacklisted: false,
    registrationAge: "26 years",
    scannedAt: new Date(Date.now() - 1000 * 60 * 12),
  },
  {
    url: "http://paypa1-secure.login-verify.tk/account/confirm",
    verdict: "phishing",
    riskScore: 94,
    checks: [],
    indicators: ["No HTTPS", "Lookalike domain", "Suspicious keywords", "Free TLD"],
    explanation: "Classic credential-harvesting phishing page.",
    recommendation: "Do not visit.",
    domain: "paypa1-secure.login-verify.tk",
    https: false,
    ipReputation: "flagged",
    subdomains: 3,
    blacklisted: true,
    registrationAge: "3 days",
    scannedAt: new Date(Date.now() - 1000 * 60 * 47),
  },
  {
    url: "https://dropbox-share.storage-files.net/doc?id=8f2a",
    verdict: "suspicious",
    riskScore: 61,
    checks: [],
    indicators: ["Brand impersonation", "Misleading subdomain"],
    explanation: "Dropbox lookalike domain — not affiliated with Dropbox Inc.",
    recommendation: "Verify before proceeding.",
    domain: "dropbox-share.storage-files.net",
    https: true,
    ipReputation: "unknown",
    subdomains: 1,
    blacklisted: false,
    registrationAge: "18 days",
    scannedAt: new Date(Date.now() - 1000 * 60 * 60 * 2),
  },
  {
    url: "https://stripe.com/payments",
    verdict: "safe",
    riskScore: 6,
    checks: [],
    indicators: [],
    explanation: "Official Stripe domain with verified TLS and clean reputation.",
    recommendation: "Safe to proceed.",
    domain: "stripe.com",
    https: true,
    ipReputation: "clean",
    subdomains: 0,
    blacklisted: false,
    registrationAge: "21 years",
    scannedAt: new Date(Date.now() - 1000 * 60 * 60 * 5),
  },
  {
    url: "http://192.168.1.1/admin/verify-user?token=abc123&redirect=paypal",
    verdict: "phishing",
    riskScore: 97,
    checks: [],
    indicators: ["IP address hostname", "No HTTPS", "Suspicious redirect", "Credential keywords"],
    explanation: "Raw IP address with phishing parameters targeting PayPal users.",
    recommendation: "Do not visit.",
    domain: "192.168.1.1",
    https: false,
    ipReputation: "flagged",
    subdomains: 0,
    blacklisted: true,
    registrationAge: "N/A",
    scannedAt: new Date(Date.now() - 1000 * 60 * 60 * 24),
  },
];
