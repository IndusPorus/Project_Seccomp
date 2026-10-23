"""Risk-based vulnerability prioritisation (beyond raw CVSS)."""
def score(cvss, exploited, criticality, internet_facing):
    s = cvss * 6                       # 0-60 base severity
    s += 20 if exploited else 0        # known exploitation in the wild
    s += 10 if internet_facing else 0  # exposure
    s += criticality * 2               # asset business criticality 1-5 => 2-10
    return min(round(s, 1), 100.0)

def priority(s):
    if s >= 85: return "P1", 7
    if s >= 65: return "P2", 30
    if s >= 40: return "P3", 60
    return "P4", 90
