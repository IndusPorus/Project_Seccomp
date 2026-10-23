"""Access-review checks: dormant, leaver, privileged-without-approval, SoD conflicts."""
from datetime import datetime, timedelta

SOD_CONFLICTS = [("payment_creator", "payment_approver"), ("developer", "prod_deployer"), ("auditor", "sysadmin")]
PRIVILEGED = {"sysadmin", "domain_admin", "prod_deployer", "db_admin"}

def review(accounts, dormant_days=90, now=None):
    now, findings = now or datetime.now(), []
    for a in accounts:
        roles = set(filter(None, a["roles"].split(",")))
        last = datetime.fromisoformat(a["last_login"]) if a["last_login"] else None
        def add(issue, sev, rec): findings.append({"user": a["user"], "issue": issue, "severity": sev, "recommendation": rec})
        if not a["enabled"] and roles:
            add("Disabled account still holds roles (leaver)", "high", "Revoke all roles")
        if a["enabled"] and (last is None or now - last > timedelta(days=dormant_days)):
            add(f"Dormant > {dormant_days} days", "medium", "Disable account / recertify with manager")
        if roles & PRIVILEGED and not a["approved_by"]:
            add("Privileged access without documented approval", "high", "Obtain approval or remove privileged role")
        for r1, r2 in SOD_CONFLICTS:
            if {r1, r2} <= roles:
                add(f"Segregation-of-duties conflict: {r1} + {r2}", "critical", "Remove one of the conflicting roles")
    return findings
