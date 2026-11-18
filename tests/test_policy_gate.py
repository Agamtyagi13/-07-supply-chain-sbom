import json
import pathlib
import sys
from datetime import date

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import policy_gate as pg  # noqa: E402

FX = ROOT / "tests" / "fixtures"
POLICY = json.loads((ROOT / "policy" / "policy.json").read_text())


def run(trivy, sbom, policy=POLICY, today=date(2026, 11, 16)):
    return pg.evaluate(
        json.loads((FX / trivy).read_text()), json.loads((FX / sbom).read_text()), policy, today
    )


def test_clean_passes():
    assert run("trivy_clean.json", "sbom_ok.json")["passed"]


def test_critical_blocks():
    r = run("trivy_critical.json", "sbom_ok.json")
    assert not r["passed"] and "CRITICAL" in r["failures"][0]


def test_high_threshold():
    assert not run("trivy_high.json", "sbom_ok.json")["passed"]


def test_unfixed_ignored():
    assert run("trivy_unfixed.json", "sbom_ok.json")["passed"]


def test_unfixed_counted_when_not_ignored():
    p = dict(POLICY, ignore_unfixed=False)
    assert not run("trivy_unfixed.json", "sbom_ok.json", p)["passed"]


def test_denied_license():
    assert not run("trivy_clean.json", "sbom_badlicense.json")["passed"]


def test_empty_sbom_blocks():
    assert not run("trivy_clean.json", "sbom_empty.json")["passed"]


def test_waiver_applies_then_expires():
    p = dict(POLICY, waivers=[{"id": "CVE-2099-0001-0", "reason": "t", "expires": "2026-12-01"}])
    assert run("trivy_critical.json", "sbom_ok.json", p, date(2026, 11, 16))["passed"]
    r = run("trivy_critical.json", "sbom_ok.json", p, date(2026, 12, 2))
    assert not r["passed"] and r["expired_waivers"] == ["CVE-2099-0001-0"]


def test_cli_exit_codes(tmp_path):
    rep = str(tmp_path / "r.md")
    args = ["--sbom", str(FX / "sbom_ok.json"), "--policy", str(ROOT / "policy/policy.json"), "--report", rep]
    assert pg.main(["--trivy", str(FX / "trivy_clean.json")] + args) == 0
    assert pg.main(["--trivy", str(FX / "trivy_critical.json")] + args) == 1
