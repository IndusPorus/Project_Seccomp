import os, tempfile
os.environ["SECOPS_DB"] = os.path.join(tempfile.mkdtemp(), "t.db")
os.environ["SECOPS_API_KEY"] = "k"
from fastapi.testclient import TestClient
from app.main import app
H = {"X-API-Key": "k"}

def test_auth_required():
    with TestClient(app) as c:
        assert c.get("/alerts").status_code == 401

def test_full_flow():
    with TestClient(app) as c:
        c.post("/seed", headers=H)
        assert c.post("/detect/run", headers=H).json()["new_alerts"] >= 4
        rules = {a["rule"] for a in c.get("/alerts", headers=H).json()}
        assert {"Brute Force", "Password Spraying", "Successful Login After Failures", "Off-Hours Privileged Activity"} <= rules
        assert c.get("/vulns", headers=H).json()[0]["priority"] == "P1"
        issues = " ".join(f["issue"] for f in c.get("/iam/review", headers=H).json()["findings"])
        assert "Segregation" in issues and "Dormant" in issues and "leaver" in issues
        assert c.post("/vulns/1/close", json={"evidence": "patched v2.17"}, headers=H).status_code == 200
        assert c.get("/dashboard", headers=H).json()["vulns_closed"] == 1

def test_validation():
    with TestClient(app) as c:
        assert c.post("/vulns", json={"asset": "x", "cve": "bad", "cvss": 5, "criticality": 2}, headers=H).status_code == 422
