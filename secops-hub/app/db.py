import os, sqlite3
DB_PATH = os.getenv("SECOPS_DB", "secops.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY, ts TEXT, source_ip TEXT, user TEXT, action TEXT, status TEXT, host TEXT);
CREATE TABLE IF NOT EXISTS alerts(id INTEGER PRIMARY KEY, ts TEXT, rule TEXT, severity TEXT, mitre TEXT, details TEXT, UNIQUE(rule, details));
CREATE TABLE IF NOT EXISTS vulns(id INTEGER PRIMARY KEY, asset TEXT, cve TEXT, cvss REAL, exploited INTEGER, criticality INTEGER,
  internet_facing INTEGER, status TEXT DEFAULT 'open', score REAL, priority TEXT, sla_days INTEGER, closure_evidence TEXT);
CREATE TABLE IF NOT EXISTS accounts(id INTEGER PRIMARY KEY, user TEXT UNIQUE, department TEXT, roles TEXT, last_login TEXT, enabled INTEGER, approved_by TEXT);
"""

def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_conn() as c:
        c.executescript(SCHEMA)
