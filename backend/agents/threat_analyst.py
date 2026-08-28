import os
import json
from typing import Dict, Any, List, Optional
import httpx

class ThreatAnalystAgent:
    """
    PhishGuard Threat Analyst Agent.
    Specialized AI agent that translates multi-dimensional detection signals
    into clear, user-friendly security explanations and actionable recommendations.
    """

    def __init__(self):
        self.openai_api_key = os.getenv("OPENAI_API_KEY")
        self.gemini_api_key = os.getenv("GEMINI_API_KEY")

    def analyze(self, scan_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Main entry point for Threat Analyst.
        Receives the structured detection engine results and returns
        summary, reasons, explanation, and recommendation.
        """
        try:
            # If an external LLM API key is present and configured, attempt fast LLM reasoning
            if self.openai_api_key:
                llm_res = self._call_openai(scan_data)
                if llm_res:
                    return llm_res

            # Default / Fallback: Deterministic expert AI reasoning engine
            return self._generate_expert_analysis(scan_data)
        except Exception as e:
            # Guaranteed fallback - never let agent errors disrupt the scan
            return self._generate_fallback(scan_data, error_info=str(e))

    def _call_openai(self, scan_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Optional OpenAI API call with strict short timeout."""
        try:
            prompt = f"""You are the PhishGuard Threat Analyst.
Analyze these scan results for {scan_data.get('url')}:
Verdict: {scan_data.get('verdict')}
Risk Score: {scan_data.get('risk_score', scan_data.get('riskScore'))}/100
Indicators: {scan_data.get('indicators', [])}
Domain: {scan_data.get('domain')}
HTTPS: {scan_data.get('https')}
Features: {scan_data.get('features', {})}

Return a valid JSON object with exact keys:
{{
  "summary": "Short 1-2 sentence threat summary",
  "reasons": ["main reason 1", "main reason 2", "main reason 3"],
  "explanation": "Clear explanation for a non-technical user",
  "recommendation": "Specific actionable safety advice"
}}"""
            headers = {
                "Authorization": f"Bearer {self.openai_api_key}",
                "Content-Type": "application/json"
            }
            payload = {
                "model": "gpt-4o-mini",
                "messages": [
                    {"role": "system", "content": "You are a cybersecurity expert providing structured threat explanations."},
                    {"role": "user", "content": prompt}
                ],
                "response_format": {"type": "json_object"},
                "temperature": 0.2,
                "max_tokens": 300
            }
            with httpx.Client(timeout=2.0) as client:
                res = client.post("https://api.openai.com/v1/chat/completions", headers=headers, json=payload)
                if res.status_code == 200:
                    data = res.json()
                    content = data["choices"][0]["message"]["content"]
                    return json.loads(content)
        except Exception:
            pass
        return None

    def _generate_expert_analysis(self, scan_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Synthesizes expert cybersecurity explanations based on the exact
        combination of signals detected.
        """
        url = scan_data.get("url", "")
        verdict = scan_data.get("verdict", "safe")
        score = scan_data.get("risk_score", scan_data.get("riskScore", 0))
        indicators = scan_data.get("indicators", [])
        features = scan_data.get("features") or {}
        domain = scan_data.get("domain", "")
        has_https = scan_data.get("https", True)
        blacklisted = scan_data.get("blacklisted", False)
        reg_age = scan_data.get("registration_age", scan_data.get("registrationAge", "Unknown"))

        reasons: List[str] = []

        # 1. High Risk / Phishing Analysis
        if verdict == "phishing" or score >= 75:
            impersonated_brand = None
            if "Lookalike domain" in str(indicators):
                for ind in indicators:
                    if "mimicking" in ind.lower() or "lookalike" in ind.lower():
                        reasons.append(ind)
                        if "mimicking" in ind.lower():
                            impersonated_brand = ind.split("mimicking")[-1].strip()

            if features.get("is_ip") or "IP address" in str(indicators):
                reasons.append("Raw numeric IP address used as hostname instead of a verified domain name")

            if not has_https or "No HTTPS" in str(indicators):
                reasons.append("Unencrypted connection (HTTP), exposing submitted credentials in plaintext")

            if blacklisted or "blacklists" in str(indicators):
                reasons.append("Domain actively listed on cybersecurity threat intelligence feeds")

            if "keywords" in str(indicators).lower() or features.get("suspicious_keywords"):
                kw_list = features.get("suspicious_keywords", [])
                if kw_list:
                    reasons.append(f"Deceptive login/credential keywords detected in URL path: {', '.join(kw_list[:3])}")
                else:
                    reasons.append("Suspicious credential-harvesting keywords found in URL path")

            if "top-level domain" in str(indicators).lower():
                reasons.append("Uses a high-risk free/disposable top-level domain frequently associated with spam campaigns")

            # Fallback if specific reasons list is short
            if not reasons:
                reasons = indicators[:3] if indicators else ["Matches known phishing heuristics and deceptive URL patterns"]

            # Craft explanation
            if impersonated_brand:
                summary = f"High-risk credential harvesting campaign mimicking {impersonated_brand}."
                explanation = (
                    f"This URL appears to be a fraudulent phishing page designed to steal sensitive account "
                    f"credentials by impersonating {impersonated_brand}. The domain is not authorized or operated "
                    f"by the legitimate service and exhibits multiple critical threat indicators."
                )
            elif features.get("is_ip"):
                summary = "Dangerous unverified direct IP connection hosting suspicious web forms."
                explanation = (
                    "Legitimate organizations host services on verified domain names with valid TLS certificates. "
                    "This link points directly to a raw IP address, a common tactic used by attackers to bypass domain controls."
                )
            else:
                summary = "Dangerous phishing website exhibiting multiple deceptive signals."
                explanation = (
                    "Our multi-layer detection engine identified multiple high-confidence phishing indicators. "
                    "Visiting this site poses an immediate risk of credential theft, session hijacking, or malware delivery."
                )

            recommendation = "Do not open this link or enter any passwords, credit card numbers, or personal credentials."

        # 2. Suspicious Analysis
        elif verdict == "suspicious" or score >= 40:
            if "Brand impersonation" in str(indicators):
                reasons.append("Subdomain structure references a recognized brand not owned by the primary domain")
            if not has_https:
                reasons.append("Connection lacks TLS encryption, leaving data vulnerable to interception")
            if reg_age != "Unknown" and ("day" in reg_age or "month" in reg_age):
                reasons.append(f"Domain is newly registered ({reg_age}), which is statistically common among short-lived threat sites")
            if "subdomain" in str(indicators).lower():
                reasons.append("Excessive subdomain depth used to obscure the true destination hostname")

            if not reasons:
                reasons = indicators[:3] if indicators else ["Anomalous URL structure requiring caution"]

            summary = "Suspicious domain characteristics detected with potential impersonation risk."
            explanation = (
                f"While not yet confirmed on global threat blacklists, this destination exhibits characteristics "
                f"commonly seen in phishing lures, such as deceptive subdomains or recent registration ({reg_age})."
            )
            recommendation = "Proceed with caution. Verify the sender and do not input passwords or sensitive financial data."

        # 3. Safe Analysis
        else:
            summary = "Verified legitimate domain with established trust and valid encryption."
            reasons = [
                "Domain is established with a clean security reputation and no active threat listings",
                "Connection is secured with a valid TLS certificate",
                "URL structure conforms to standard web conventions without obfuscation"
            ]
            explanation = (
                f"The domain '{domain}' appears legitimate. Multi-layer inspection detected no malicious "
                f"redirects, lookalike patterns, or threat database flags."
            )
            recommendation = "Safe to visit. Continue to practice normal browsing safety."

        return {
            "summary": summary,
            "reasons": reasons,
            "explanation": explanation,
            "recommendation": recommendation
        }

    def _generate_fallback(self, scan_data: Dict[str, Any], error_info: str = "") -> Dict[str, Any]:
        """Simple fallback in case of unexpected exceptions."""
        verdict = scan_data.get("verdict", "safe")
        indicators = scan_data.get("indicators", [])
        
        return {
            "summary": f"Automated analysis completed: {verdict.upper()}",
            "reasons": indicators[:3] if indicators else ["Scan completed by PhishGuard Heuristic Engine"],
            "explanation": scan_data.get("explanation", "URL safety analysis completed."),
            "recommendation": scan_data.get("recommendation", "Exercise caution when visiting unfamiliar links.")
        }

# Global singleton instance
threat_analyst_agent = ThreatAnalystAgent()
