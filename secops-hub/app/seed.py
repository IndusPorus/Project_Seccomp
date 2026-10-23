"""Generates realistic demo data so every endpoint has something to show."""
from datetime import datetime, timedelta

def sample_events():
    base = datetime.now().replace(hour=14, minute=0, second=0, microsecond=0)
    ev = lambda m, ip, u, a, s, h="srv-web-01": dict(ts=(base + timedelta(minutes=m)).isoformat(), source_ip=ip, user=u, action=a, status=s, host=h)
    out = [ev(i, "203.0.113.50", "admin", "login", "failure") for i in range(6)]            # brute force
    out.append(ev(7, "203.0.113.50", "admin", "login", "success"))                          # then success
    out += [ev(10 + i, "198.51.100.7", f"user{i}", "login", "failure") for i in range(6)]   # spraying
    out.append(dict(ts=base.replace(hour=2).isoformat(), source_ip="10.0.0.5", user="svc_backup",
                    action="privilege_escalation", status="success", host="db-prod-02"))     # off-hours
    out += [ev(30, "10.0.0.20", "alice", "login", "success")]                                # benign
    return out

def sample_vulns():
    return [
        dict(asset="payments-gw", cve="CVE-2021-44228", cvss=10.0, exploited=True, criticality=5, internet_facing=True),
        dict(asset="hr-portal", cve="CVE-2023-4863", cvss=8.8, exploited=True, criticality=3, internet_facing=True),
        dict(asset="file-srv-03", cve="CVE-2022-26134", cvss=9.8, exploited=False, criticality=3, internet_facing=False),
        dict(asset="dev-laptop-17", cve="CVE-2020-1472", cvss=5.5, exploited=False, criticality=1, internet_facing=False),
    ]

def sample_accounts():
    d = lambda n: (datetime.now() - timedelta(days=n)).isoformat()
    return [
        dict(user="alice", department="Payments", roles="payment_creator,payment_approver", last_login=d(2), enabled=1, approved_by="mgr1"),
        dict(user="bob", department="IT", roles="sysadmin", last_login=d(5), enabled=1, approved_by=None),
        dict(user="carol", department="Finance", roles="viewer", last_login=d(200), enabled=1, approved_by="mgr2"),
        dict(user="dave", department="Dev", roles="developer,prod_deployer", last_login=d(1), enabled=1, approved_by="mgr3"),
        dict(user="erin", department="HR", roles="db_admin", last_login=d(40), enabled=0, approved_by="mgr4"),
    ]
