#!/usr/bin/env python3
"""Release policy gate.

Inputs : Trivy JSON report, CycloneDX SBOM (from Syft), policy.json
Output : Markdown report on stdout (also written to --report), exit code 1 on breach.
"""
import argparse
import json
import sys
from datetime import date

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")


def load(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def active_waivers(policy, today):
    ok = {}
    expired = []
    for w in policy.get("waivers", []):
        exp = date.fromisoformat(w["expires"])
        if exp >= today:
            ok[w["id"]] = w
        else:
            expired.append(w["id"])
    return ok, expired


def collect_vulns(trivy, ignore_unfixed, waivers):
    counts = {s: 0 for s in SEVERITIES}
    findings, waived = [], []
    for res in trivy.get("Results", []) or []:
        for v in res.get("Vulnerabilities", []) or []:
            sev = v.get("Severity", "UNKNOWN")
            if ignore_unfixed and not v.get("FixedVersion"):
                continue
            if v["VulnerabilityID"] in waivers:
                waived.append(v["VulnerabilityID"])
                continue
            counts[sev] = counts.get(sev, 0) + 1
            findings.append(v)
    return counts, findings, waived


def license_violations(sbom, denied):
    bad = []
    for c in sbom.get("components", []) or []:
        for lic in c.get("licenses", []) or []:
            ident = (lic.get("license") or {}).get("id") or lic.get("expression")
            if ident in denied:
                bad.append((c.get("name"), c.get("version"), ident))
    return bad


def evaluate(trivy, sbom, policy, today=None):
    today = today or date.today()
    waivers, expired = active_waivers(policy, today)
    counts, findings, waived = collect_vulns(
        trivy, policy.get("ignore_unfixed", False), waivers
    )
    n_components = len(sbom.get("components", []) or [])
    lic = license_violations(sbom, set(policy.get("denied_licenses", [])))

    failures = []
    if counts["CRITICAL"] > policy["max_critical"]:
        failures.append(f"CRITICAL vulnerabilities {counts['CRITICAL']} > {policy['max_critical']}")
    if counts["HIGH"] > policy["max_high"]:
        failures.append(f"HIGH vulnerabilities {counts['HIGH']} > {policy['max_high']}")
    if n_components < policy.get("require_sbom_components_min", 1):
        failures.append(f"SBOM has {n_components} components (minimum {policy['require_sbom_components_min']})")
    for name, ver, ident in lic:
        failures.append(f"Denied license {ident} in {name}@{ver}")
    return {
        "passed": not failures,
        "failures": failures,
        "counts": counts,
        "findings": findings,
        "waived": waived,
        "expired_waivers": expired,
        "components": n_components,
    }


def render(result):
    lines = ["## Release policy gate", ""]
    lines.append("**Result: " + ("PASS" if result["passed"] else "BLOCKED") + "**")
    lines += ["", f"SBOM components: {result['components']}", "", "| Severity | Count |", "|---|---|"]
    for s in SEVERITIES:
        lines.append(f"| {s} | {result['counts'][s]} |")
    if result["waived"]:
        lines += ["", "Waived: " + ", ".join(sorted(set(result["waived"])))]
    if result["expired_waivers"]:
        lines += ["", "Expired waivers (no longer applied): " + ", ".join(result["expired_waivers"])]
    if result["failures"]:
        lines += ["", "### Policy breaches"] + [f"- {f}" for f in result["failures"]]
        crit = [v for v in result["findings"] if v.get("Severity") == "CRITICAL"]
        if crit:
            lines += ["", "### Critical findings"]
            for v in crit:
                lines.append(
                    f"- {v['VulnerabilityID']} {v.get('PkgName')} {v.get('InstalledVersion')} "
                    f"(fixed: {v.get('FixedVersion') or 'n/a'})"
                )
    return "\n".join(lines) + "\n"


def main(argv=None):
    p = argparse.ArgumentParser()
    p.add_argument("--trivy", required=True)
    p.add_argument("--sbom", required=True)
    p.add_argument("--policy", required=True)
    p.add_argument("--report", default="policy-report.md")
    a = p.parse_args(argv)
    result = evaluate(load(a.trivy), load(a.sbom), load(a.policy))
    text = render(result)
    with open(a.report, "w", encoding="utf-8") as fh:
        fh.write(text)
    sys.stdout.write(text)
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
