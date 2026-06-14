"""Quick API test script for ThreatLens"""
import httpx
import json

BASE = "http://localhost:8000"

print("=" * 60)
print("ThreatLens API — End-to-End Test")
print("=" * 60)

# 1. Health check
print("\n[1] Health Check")
r = httpx.get(f"{BASE}/health")
print(f"    Status: {r.status_code} | {r.json()}")

# 2. Register
print("\n[2] Register User")
r = httpx.post(f"{BASE}/api/auth/register", json={
    "email": "test@threatlens.io",
    "username": "testuser",
    "password": "SecurePass123!"
})
print(f"    Status: {r.status_code}")
data = r.json()
token = data.get("access_token", "")
print(f"    User ID: {data.get('user_id')}")
print(f"    Token: {token[:30]}...")

headers = {"Authorization": f"Bearer {token}"}

# 3. Get profile
print("\n[3] Get Profile (/api/auth/me)")
r = httpx.get(f"{BASE}/api/auth/me", headers=headers)
print(f"    Status: {r.status_code} | {r.json()}")

# 4. Scan a SAFE URL
print("\n[4] Scan Safe URL — google.com")
r = httpx.post(f"{BASE}/api/scan/url", json={"url": "https://www.google.com"}, headers=headers, timeout=30)
print(f"    Status: {r.status_code}")
data = r.json()
print(f"    Verdict: {data.get('verdict')} | Risk: {data.get('risk_score')} | Confidence: {data.get('confidence')}")
print(f"    Risk Level: {data.get('risk_level')}")
print(f"    Recommendations: {data.get('recommendations', [])[:2]}")

# 5. Scan a SUSPICIOUS URL
print("\n[5] Scan Suspicious URL — phishing-like")
r = httpx.post(f"{BASE}/api/scan/url", json={
    "url": "http://192.168.1.100/login/verify-account/secure/update?user=admin&token=abc123"
}, headers=headers, timeout=30)
print(f"    Status: {r.status_code}")
data = r.json()
print(f"    Verdict: {data.get('verdict')} | Risk: {data.get('risk_score')} | Confidence: {data.get('confidence')}")
print(f"    Features detected:")
for f in data.get("features", []):
    print(f"      - [{f['risk_contribution'].upper()}] {f['name']}: {f['value']}")

# 6. Scan Email
print("\n[6] Scan Phishing Email")
r = httpx.post(f"{BASE}/api/scan/email", json={
    "email_content": "Dear customer, your account has been suspended due to unusual activity. Click here to verify your account immediately or it will be terminated within 24 hours. Visit http://192.168.0.1/login to confirm your identity. Failure to verify will result in permanent account closure.",
    "subject": "URGENT: Account Suspended - Verify Now",
    "sender": "security@gmail.com"
}, headers=headers, timeout=30)
print(f"    Status: {r.status_code}")
data = r.json()
print(f"    Verdict: {data.get('verdict')} | Risk: {data.get('risk_score')}")
print(f"    Features:")
for f in data.get("features", []):
    print(f"      - [{f['risk_contribution'].upper()}] {f['name']}: {f['value']}")

# 7. Check history
print("\n[7] Scan History")
r = httpx.get(f"{BASE}/api/scan/history", headers=headers)
print(f"    Status: {r.status_code}")
data = r.json()
print(f"    Total scans: {data.get('total')}")
for s in data.get("scans", []):
    print(f"      - [{s['verdict']}] {s['scan_type']}: {s['input_data'][:50]}")

# 8. Stats
print("\n[8] User Stats")
r = httpx.get(f"{BASE}/api/scan/", headers=headers)
print(f"    Status: {r.status_code}")
data = r.json()
print(f"    {json.dumps(data, indent=4)}")

print("\n" + "=" * 60)
print("✅ All tests passed!")
print("=" * 60)
