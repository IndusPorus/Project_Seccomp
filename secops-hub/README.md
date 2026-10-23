# SecOps Hub – Cyber Security Backend (FastAPI + SQLite)

Maps to the SG Cyber Security Analyst JD: **Security Operations, Vulnerability Management, IAM governance, reporting**.

## Run in VS Code
```bash
python -m venv venv
venv\Scripts\activate          # Windows   (Mac/Linux: source venv/bin/activate)
pip install -r requirements.txt
uvicorn app.main:app --reload
```
Open **http://127.0.0.1:8000/docs** → click **Authorize** → enter `dev-key-change-me`.
Then try: `POST /seed` → `POST /detect/run` → `GET /alerts`, `/vulns`, `/iam/review`, `/dashboard`.
Run tests: `pytest -q`. Change key: set env var `SECOPS_API_KEY`.

## Modules
| File | What it does |
|---|---|
| `app/detection.py` | Brute force, password spraying, success-after-failures, off-hours privileged activity (MITRE ATT&CK T1110, T1078) |
| `app/vulns.py` | Risk score = CVSS + exploited + internet-facing + asset criticality → P1–P4 with SLA days |
| `app/iam.py` | Dormant accounts, leavers with roles, privileged w/o approval, Segregation-of-Duties conflicts |
| `app/main.py` | REST API, API-key auth, input validation (Pydantic), parameterised SQL |

## Security practices built in
API-key auth · strict validation (IP/CVE regex, ranges) · parameterised queries (no SQL injection) · closure evidence required to close a vuln · alert de-duplication.

## Extension ideas (for interviews)
Add a PowerShell/Python log collector, JWT + roles, Docker, a React dashboard, VirusTotal/NVD API enrichment, or an ML anomaly detector.
