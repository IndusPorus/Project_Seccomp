import os
from typing import List, Optional
from fastapi import FastAPI, Depends, Header, HTTPException, Query
from pydantic import BaseModel, Field
from . import db, detection, vulns as vm, iam, seed

API_KEY = os.getenv("SECOPS_API_KEY", "dev-key-change-me")
app = FastAPI(title="SecOps Hub", version="1.0", description="SOC alerts, vulnerability management & IAM review API")

def auth(x_api_key: str = Header(None)):
    if x_api_key != API_KEY:
        raise HTTPException(401, "Invalid or missing X-API-Key")

@app.on_event("startup")
def _startup(): db.init_db()

# ---------- models (input validation) ----------
class Event(BaseModel):
    ts: str; source_ip: str = Field(pattern=r"^\d{1,3}(\.\d{1,3}){3}$"); user: str
    action: str; status: str = Field(pattern="^(success|failure)$"); host: str = "unknown"

class Vuln(BaseModel):
    asset: str; cve: str = Field(pattern=r"^CVE-\d{4}-\d{4,}$"); cvss: float = Field(ge=0, le=10)
    exploited: bool = False; criticality: int = Field(ge=1, le=5); internet_facing: bool = False

class Account(BaseModel):
    user: str; department: str = ""; roles: str = ""; last_login: Optional[str] = None
    enabled: bool = True; approved_by: Optional[str] = None

class Closure(BaseModel):
    evidence: str = Field(min_length=5)

# ---------- security operations ----------
@app.post("/events", dependencies=[Depends(auth)])
def ingest(events: List[Event]):
    with db.get_conn() as c:
        c.executemany("INSERT INTO events(ts,source_ip,user,action,status,host) VALUES(?,?,?,?,?,?)",
                      [(e.ts, e.source_ip, e.user, e.action, e.status, e.host) for e in events])
    return {"ingested": len(events)}

@app.post("/detect/run", dependencies=[Depends(auth)])
def run_detection():
    with db.get_conn() as c:
        events = [dict(r) for r in c.execute("SELECT * FROM events")]
        new = 0
        for rule, sev, mitre, details, ts in detection.run_rules(events):
            cur = c.execute("INSERT OR IGNORE INTO alerts(ts,rule,severity,mitre,details) VALUES(?,?,?,?,?)", (ts, rule, sev, mitre, details))
            new += cur.rowcount
    return {"events_analysed": len(events), "new_alerts": new}

@app.get("/alerts", dependencies=[Depends(auth)])
def alerts(severity: Optional[str] = Query(None, pattern="^(medium|high|critical)$")):
    q, args = "SELECT * FROM alerts", []
    if severity: q, args = q + " WHERE severity=?", [severity]
    with db.get_conn() as c:
        return [dict(r) for r in c.execute(q + " ORDER BY id DESC", args)]

# ---------- vulnerability management ----------
@app.post("/vulns", dependencies=[Depends(auth)])
def add_vuln(v: Vuln):
    s = vm.score(v.cvss, v.exploited, v.criticality, v.internet_facing); p, sla = vm.priority(s)
    with db.get_conn() as c:
        cur = c.execute("INSERT INTO vulns(asset,cve,cvss,exploited,criticality,internet_facing,score,priority,sla_days) VALUES(?,?,?,?,?,?,?,?,?)",
                        (v.asset, v.cve, v.cvss, v.exploited, v.criticality, v.internet_facing, s, p, sla))
    return {"id": cur.lastrowid, "risk_score": s, "priority": p, "sla_days": sla}

@app.get("/vulns", dependencies=[Depends(auth)])
def list_vulns(status: Optional[str] = None):
    q, args = "SELECT * FROM vulns", []
    if status: q, args = q + " WHERE status=?", [status]
    with db.get_conn() as c:
        return [dict(r) for r in c.execute(q + " ORDER BY score DESC", args)]

@app.post("/vulns/{vid}/close", dependencies=[Depends(auth)])
def close_vuln(vid: int, body: Closure):
    with db.get_conn() as c:
        cur = c.execute("UPDATE vulns SET status='closed', closure_evidence=? WHERE id=?", (body.evidence, vid))
    if not cur.rowcount: raise HTTPException(404, "Vulnerability not found")
    return {"id": vid, "status": "closed"}

# ---------- identity & access management ----------
@app.post("/iam/accounts", dependencies=[Depends(auth)])
def add_account(a: Account):
    try:
        with db.get_conn() as c:
            c.execute("INSERT INTO accounts(user,department,roles,last_login,enabled,approved_by) VALUES(?,?,?,?,?,?)",
                      (a.user, a.department, a.roles, a.last_login, a.enabled, a.approved_by))
    except Exception:
        raise HTTPException(409, "Account already exists")
    return {"created": a.user}

@app.get("/iam/review", dependencies=[Depends(auth)])
def access_review(dormant_days: int = Query(90, ge=1)):
    with db.get_conn() as c:
        findings = iam.review([dict(r) for r in c.execute("SELECT * FROM accounts")], dormant_days)
    return {"total_findings": len(findings), "findings": findings}

# ---------- reporting ----------
@app.get("/dashboard", dependencies=[Depends(auth)])
def dashboard():
    with db.get_conn() as c:
        one = lambda q: c.execute(q).fetchone()[0]
        return {
            "alerts_by_severity": {r[0]: r[1] for r in c.execute("SELECT severity, COUNT(*) FROM alerts GROUP BY severity")},
            "open_vulns_by_priority": {r[0]: r[1] for r in c.execute("SELECT priority, COUNT(*) FROM vulns WHERE status='open' GROUP BY priority")},
            "vulns_closed": one("SELECT COUNT(*) FROM vulns WHERE status='closed'"),
            "accounts_total": one("SELECT COUNT(*) FROM accounts"),
            "top_risk": [dict(r) for r in c.execute("SELECT asset,cve,score,priority FROM vulns WHERE status='open' ORDER BY score DESC LIMIT 3")],
        }

@app.post("/seed", dependencies=[Depends(auth)])
def seed_demo():
    ingest([Event(**e) for e in seed.sample_events()])
    for v in seed.sample_vulns(): add_vuln(Vuln(**v))
    for a in seed.sample_accounts():
        try: add_account(Account(**a))
        except HTTPException: pass
    return {"seeded": True}
