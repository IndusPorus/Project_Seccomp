"""Rule-based detection engine. Each rule maps to a MITRE ATT&CK technique."""
from collections import defaultdict
from datetime import datetime, timedelta

def _t(s): return datetime.fromisoformat(s)

def run_rules(events, window_min=5, brute_threshold=5, spray_threshold=5):
    alerts, fails_by_ip = [], defaultdict(list)
    for e in sorted(events, key=lambda e: e["ts"]):
        if e["action"] == "login" and e["status"] == "failure":
            fails_by_ip[e["source_ip"]].append(e)
    win = timedelta(minutes=window_min)

    for ip, fails in fails_by_ip.items():
        for i, f in enumerate(fails):
            burst = [x for x in fails[i:] if _t(x["ts"]) - _t(f["ts"]) <= win]
            users = {x["user"] for x in burst}
            if len(users) >= spray_threshold:
                alerts.append(("Password Spraying", "high", "T1110.003",
                               f"{ip} failed logins against {len(users)} users in {window_min}min", f["ts"]))
                break
            if len(burst) >= brute_threshold:
                alerts.append(("Brute Force", "high", "T1110.001",
                               f"{ip} had {len(burst)} failed logins ({burst[0]['user']}) in {window_min}min", f["ts"]))
                break

    # success after repeated failures => possible credential compromise
    for e in events:
        if e["action"] == "login" and e["status"] == "success":
            prior = [f for f in fails_by_ip.get(e["source_ip"], [])
                     if f["user"] == e["user"] and timedelta(0) <= _t(e["ts"]) - _t(f["ts"]) <= win]
            if len(prior) >= 3:
                alerts.append(("Successful Login After Failures", "critical", "T1078",
                               f"{e['user']} logged in from {e['source_ip']} after {len(prior)} failures", e["ts"]))

    # privileged/sensitive activity off-hours
    for e in events:
        if e["action"] in ("privilege_escalation", "admin_login") and not (7 <= _t(e["ts"]).hour < 20):
            alerts.append(("Off-Hours Privileged Activity", "medium", "T1078.002",
                           f"{e['user']} performed {e['action']} on {e['host']} at {e['ts']}", e["ts"]))
    return alerts
