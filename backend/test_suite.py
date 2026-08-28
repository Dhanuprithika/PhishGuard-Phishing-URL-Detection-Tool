from fastapi.testclient import TestClient
from backend.main import app

client = TestClient(app)

def test_health():
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "healthy"
    print("[PASS] Health Check Test Passed")

def test_safe_url():
    res = client.post("/api/scan", json={"url": "https://github.com"})
    assert res.status_code == 200
    data = res.json()
    assert data["verdict"] == "safe"
    assert data["riskScore"] < 20
    assert data["https"] is True
    print(f"[PASS] Safe URL Test Passed: {data['url']} -> Score: {data['riskScore']}, Verdict: {data['verdict']}")

def test_suspicious_url():
    res = client.post("/api/scan", json={"url": "https://dropbox-share.files.net/doc"})
    assert res.status_code == 200
    data = res.json()
    assert data["verdict"] in ["suspicious", "phishing"]
    assert data["riskScore"] >= 40
    print(f"[PASS] Suspicious URL Test Passed: {data['url']} -> Score: {data['riskScore']}, Verdict: {data['verdict']}")

def test_phishing_url():
    res = client.post("/api/scan", json={"url": "http://paypa1-verify.tk/login"})
    assert res.status_code == 200
    data = res.json()
    assert data["verdict"] == "phishing"
    assert data["riskScore"] >= 75
    assert len(data["indicators"]) > 0
    print(f"[PASS] Phishing URL Test Passed: {data['url']} -> Score: {data['riskScore']}, Verdict: {data['verdict']}, Indicators: {data['indicators']}")

def test_ip_hostname_phishing():
    res = client.post("/api/scan", json={"url": "http://192.168.1.1/admin/verify?paypal=1"})
    assert res.status_code == 200
    data = res.json()
    assert data["verdict"] == "phishing"
    assert data["riskScore"] >= 75
    print(f"[PASS] Raw IP Test Passed: {data['url']} -> Score: {data['riskScore']}, Verdict: {data['verdict']}")

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
    print("\n--- RUNNING PHISHGUARD BACKEND TEST SUITE ---")
    test_health()
    test_safe_url()
    test_suspicious_url()
    test_phishing_url()
    test_ip_hostname_phishing()
    test_empty_url_handling()
    test_features_endpoint()
    print("--- ALL TEST SUITE RUNS PASSED SUCCESSFULLY! ---\n")
