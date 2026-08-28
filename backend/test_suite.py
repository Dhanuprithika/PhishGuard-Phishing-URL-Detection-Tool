from fastapi.testclient import TestClient
from backend.main import app
from backend.agents.threat_analyst import threat_analyst_agent

client = TestClient(app)

def test_health():
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "healthy"
    print("[PASS] Health Check Test Passed")

def test_safe_url():
    res = client.post("/api/scan", json={"url": "https://google.com"})
    assert res.status_code == 200
    data = res.json()
    assert data["verdict"] == "safe"
    assert data["riskScore"] < 20
    assert data["https"] is True
    assert "threatAnalysis" in data or "threat_analysis" in data
    ta = data.get("threatAnalysis") or data.get("threat_analysis")
    assert ta is not None
    assert "summary" in ta
    assert "reasons" in ta
    assert "explanation" in ta
    assert "recommendation" in ta
    print(f"[PASS] Safe URL (Google) Test Passed -> Score: {data['riskScore']}, Analyst Summary: {ta['summary']}")

def test_phishing_url():
    res = client.post("/api/scan", json={"url": "http://paypa1-verify.tk/login"})
    assert res.status_code == 200
    data = res.json()
    assert data["verdict"] == "phishing"
    assert data["riskScore"] >= 75
    assert len(data["indicators"]) > 0
    ta = data.get("threatAnalysis") or data.get("threat_analysis")
    assert ta is not None
    assert "Paypal" in ta["summary"] or "Paypal" in ta["explanation"] or any("Paypal" in r for r in ta["reasons"])
    print(f"[PASS] Phishing URL (PayPal Lookalike) Test Passed -> Score: {data['riskScore']}, Analyst Summary: {ta['summary']}")

def test_suspicious_url():
    res = client.post("/api/scan", json={"url": "https://dropbox-share.files.net/doc"})
    assert res.status_code == 200
    data = res.json()
    assert data["verdict"] in ["suspicious", "phishing"]
    assert data["riskScore"] >= 40
    print(f"[PASS] Suspicious URL Test Passed: {data['url']} -> Score: {data['riskScore']}, Verdict: {data['verdict']}")

def test_ip_hostname_phishing():
    res = client.post("/api/scan", json={"url": "http://192.168.1.1/admin/verify?paypal=1"})
    assert res.status_code == 200
    data = res.json()
    assert data["verdict"] == "phishing"
    assert data["riskScore"] >= 75
    print(f"[PASS] Raw IP Test Passed: {data['url']} -> Score: {data['riskScore']}, Verdict: {data['verdict']}")

def test_threat_analyst_fallback():
    # Test agent with minimal / edge case payload
    res = threat_analyst_agent.analyze({"url": "https://unknown-edge-case.com", "verdict": "suspicious", "risk_score": 50})
    assert res is not None
    assert "summary" in res
    assert "reasons" in res
    assert "explanation" in res
    assert "recommendation" in res
    print("[PASS] Threat Analyst Fallback Test Passed")

def test_empty_url_handling():
    res = client.post("/api/scan", json={"url": ""})
    assert res.status_code == 400
    print("[PASS] Empty URL Validation Test Passed")

def test_features_endpoint():
    res = client.post("/api/features", json={"url": "https://example.com/test"})
    assert res.status_code == 200
    data = res.json()
    assert "entropy" in data
    assert "url_length" in data
    print("[PASS] Features Endpoint Test Passed")

if __name__ == "__main__":
    print("\n--- RUNNING PHISHGUARD & THREAT ANALYST TEST SUITE ---")
    test_health()
    test_safe_url()
    test_phishing_url()
    test_suspicious_url()
    test_ip_hostname_phishing()
    test_threat_analyst_fallback()
    test_empty_url_handling()
    test_features_endpoint()
    print("--- ALL TEST SUITE RUNS PASSED SUCCESSFULLY! ---\n")
