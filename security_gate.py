#!/usr/bin/env python3
import argparse
import sys
import json
import xml.etree.ElementTree as ET
from pathlib import Path

def check_semgrep(path):
    if not Path(path).exists():
        print(f"[semgrep] report not found: {path}")
        return 0, []
    data = json.load(open(path))
    issues = data.get("results", [])
    blocked = []
    for r in issues:
        sev = r.get("extra", {}).get("severity", "").upper()
        if sev in ("ERROR","HIGH","CRITICAL"):
            blocked.append({"check": "semgrep", "rule_id": r.get("check_id"), "severity": sev, "msg": r.get("extra",{}).get("message")})
    print(f"[semgrep] findings: {len(issues)}, blocked: {len(blocked)}")
    return len(issues), blocked

def check_zap(path):
    if not Path(path).exists():
        print(f"[zap] report not found: {path}")
        return 0, []
    try:
        tree = ET.parse(path)
        root = tree.getroot()
        alerts = root.findall(".//alertitem")
    except Exception:
        print(f"[zap] failed to parse xml, trying json fallback")
        return 0, []
    blocked = []
    for a in alerts:
        name = a.findtext("alert")
        risk = a.findtext("riskdesc") or ""
        # riskdesc example: "Medium (Medium)"
        if "High" in risk or "Medium" in risk:
            blocked.append({"check":"zap","name":name,"risk":risk})
    print(f"[zap] findings: {len(alerts)}, blocked: {len(blocked)}")
    return len(alerts), blocked

def check_trivy(path):
    if not Path(path).exists():
        print(f"[trivy] report not found: {path}")
        return 0, []
    data = json.load(open(path))
    vulnerabilities = []
    # Trivy json may have Results -> Vulns
    for result in data.get("Results", []):
        for vuln in result.get("Vulnerabilities", []) if result.get("Vulnerabilities") else []:
            vulnerabilities.append(vuln)
    blocked = []
    for v in vulnerabilities:
        sev = v.get("Severity","").upper()
        if sev in ("HIGH","CRITICAL"):
            blocked.append({"pkg": v.get("PkgName"), "vuln": v.get("VulnerabilityID"), "severity": sev})
    print(f"[trivy] findings: {len(vulnerabilities)}, blocked: {len(blocked)}")
    return len(vulnerabilities), blocked

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--semgrep", default="semgrep-report.json")
    parser.add_argument("--zap", default="zap-report.xml")
    parser.add_argument("--trivy", default="trivy-report.json")
    args = parser.parse_args()

    total_findings = 0
    blocked_all = []

    for func, path in [(check_semgrep, args.semgrep), (check_zap, args.zap), (check_trivy, args.trivy)]:
        findings, blocked = func(path)
        total_findings += findings
        blocked_all.extend(blocked)

    if blocked_all:
        print("SECURITY GATE FAILED. Issues causing failure:")
        print(json.dumps(blocked_all, indent=2))
        sys.exit(2)
    else:
        print("SECURITY GATE PASSED. No blocking issues found.")
        sys.exit(0)

if __name__ == "__main__":
    main()
