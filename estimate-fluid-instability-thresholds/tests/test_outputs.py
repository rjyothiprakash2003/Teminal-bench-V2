"""Verification for stratified shear fluid instability threshold estimator."""

from __future__ import annotations

import hashlib
import json
import math
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

REPORT_PATH = Path("/app/build/instability_threshold_report.json")
REPORT_FIRST = Path("/logs/verifier/report_first.json")
VERIFIER_DIR = Path("/logs/verifier")
FIXTURE_DIR = Path("/app/flow_suites")
MANIFEST_PATH = FIXTURE_DIR / "manifest.json"
APP_DIR = Path("/app")

IMMUTABLE_SHA256: dict[str, str] = {
    "Makefile": "52c7510f45708f91582675cd0f846984d01db0a3700f66da048f5321a2adfece",
    "go.mod": "4c33645ed88974e402492a8de618f36eb4190edf8071f4cbbeb2088a928b74a8",
    "thresh_contract/instability_admission_contract.json": "f1ca15144a00fc3eb2838c6307d8f4f87de1a105ac0124ee53ba5c9f7abcb2df",
    "flow_suites/manifest.json": "9d0f3527961f1c63a75f93fcdc852d8243ff149dbfc0ed52171de9da4468e0c4",
    "flow_suites/case_01.json": "befb7d602b11da55ecd0ebb0010afad6b65adacee5318db46055915142637c82",
    "flow_suites/case_02.json": "5fe1900e687aa78e6ffd3d58576f47a7acc7bd0eb83df19ee762046163d95ef4",
    "flow_suites/case_03.json": "5a334ed5d2273e79151bfafbf86b3496faefb2d045039c20bedc4c9cad252739",
    "flow_suites/case_04.json": "0eb5544b94017bd2d9c24162b192b1ece4b4b531ca0a42f1abca07058af62e95",
    "flow_suites/case_05.json": "65d17fb88a863654a98e02cc51cf99b738ed22dc660056e6917136dcfb06dbfc",
    "flow_suites/case_06.json": "5eafd8b1fc6a239097db53c14580d3089f068c08934c86be9ebc182074a740c3",
    "flow_suites/case_07.json": "3056234ca52383fec1348f36697ad68318efdfe46fe6006edb1f55f783af40b6",
    "flow_suites/case_08.json": "2ceb29c5041d8455f6e215e4d79ab2ac966dc08e2ecf733838a672c4e39bbf88",
    "flow_suites/case_09.json": "2dc398f5da12f9d7dabdb93601f89d9869bac128892f0d4206872467e673f390",
    "flow_suites/case_10.json": "fa5482656c3ffc51e1beae0abfff9bb30ae37a3444d8231ebf86b46f021deb04",
    "flow_suites/case_11.json": "7b7aadcdaab64bad98a52f7eaf15af3bd81622cbe79fadbc8ae0aaf6d83271ad",
    "flow_suites/case_12.json": "932ceaeda3f1df8bb73682b84a8f07f83948915aeaddd6cf17c4ec045a7b9192",
    "flow_suites/case_13.json": "bb9c260455f0f2c8d592006788b60ba10169dabe11fc3bbfb2ffce47a231725e",
    "flow_suites/case_14.json": "4a9dcde8017b1792cb5c2c9abf0fb557f132607fe488c568f4e9d1799052dadb",
    "flow_suites/case_15.json": "9b87001aea3919675be6b962845a4d22dc7552ffc2b1072b9eb39970e0432bd9",
    "flow_suites/case_16.json": "f07f8bfbb2a28aa541e172edc51182a29d80145ca2963278ed3338eb9ac7a3bb",
    "flow_suites/case_17.json": "c0fc60e9033ac845bbae28193ef98acb56217f30a4ac7d5b7d666c191042c9bc",
    "flow_suites/case_18.json": "fb6662c901b08f7d02066b712f76e657506ddc1f23d05513882a573213f7d6f6",
    "flow_suites/case_19.json": "c65bdee451d3b3c2ea47a90b0990f5b495331fe2597c5612b424a937bed1953d",
    "flow_suites/case_20.json": "7c009956557088ee865fb26b2b8ff7e5a431ff570064220cd2b116a0a20be932",
}

SOFT_KINDS = {
    "GROWTH_MISS",
    "UNDER_RESOLVED",
    "MASS_DRIFT",
    "MOM_DRIFT",
    "SOLVER_SPLIT",
    "RI_MISCLASS",
}




def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _perturb_case_01() -> None:
    path = FIXTURE_DIR / "case_01.json"
    obj = json.loads(path.read_text(encoding="utf-8"))
    shutil.copy(path, VERIFIER_DIR / "case_01_clean.json")
    obj["n2"] = 0.01
    path.write_text(json.dumps(obj, indent=2) + "\n", encoding="utf-8")


def _perturb_case_04() -> None:
    path = FIXTURE_DIR / "case_04.json"
    obj = json.loads(path.read_text(encoding="utf-8"))
    shutil.copy(path, VERIFIER_DIR / "case_04_clean.json")
    obj["cfl"] = 1.2
    path.write_text(json.dumps(obj, indent=2) + "\n", encoding="utf-8")


def _run_make(target: str, log_name: str) -> None:
    proc = subprocess.run(
        ["make", "-C", "/app", target],
        capture_output=True,
        text=True,
        check=False,
    )
    VERIFIER_DIR.mkdir(parents=True, exist_ok=True)
    (VERIFIER_DIR / log_name).write_text(proc.stdout + proc.stderr, encoding="utf-8")
    if proc.returncode != 0:
        pytest.fail(f"make {target} failed; see /logs/verifier/{log_name}")


def _assert_byte_identical_rerun(prefix: str) -> None:
    REPORT_PATH.unlink(missing_ok=True)
    _run_make("run", f"{prefix}_restore.log")
    shutil.copy(REPORT_PATH, REPORT_FIRST)
    _run_make("run", f"{prefix}_restore2.log")
    if REPORT_PATH.read_bytes() != REPORT_FIRST.read_bytes():
        pytest.fail(f"{prefix} rerun not byte-identical")


def _case_row(report: dict[str, Any], case_id: str) -> dict[str, Any]:
    for row in report["cases"]:
        if row["case_id"] == case_id:
            return row
    raise KeyError(case_id)


@pytest.fixture(scope="session", autouse=True)
def _verifier_grading_setup() -> None:
    """Build once and prove byte identical reruns without asserting finding detail text."""
    VERIFIER_DIR.mkdir(parents=True, exist_ok=True)
    for name in ("case_01_clean.json", "case_04_clean.json", "report_first.json"):
        (VERIFIER_DIR / name).unlink(missing_ok=True)
    for path in VERIFIER_DIR.glob("*.log"):
        path.unlink()

    _perturb_case_01()
    REPORT_PATH.unlink(missing_ok=True)
    _run_make("build", "build.log")
    _run_make("run", "run_c01.log")
    shutil.copy(REPORT_PATH, REPORT_FIRST)
    _run_make("run", "run_c01_2.log")
    if REPORT_PATH.read_bytes() != REPORT_FIRST.read_bytes():
        pytest.fail("case_01 perturbed rerun not byte-identical")
    row = _case_row(json.loads(REPORT_PATH.read_text(encoding="utf-8")), "case_01")
    assert row["status"] == "UNSTABLE"

    shutil.copy(VERIFIER_DIR / "case_01_clean.json", FIXTURE_DIR / "case_01.json")

    _perturb_case_04()
    _assert_byte_identical_rerun("c04")
    row = _case_row(json.loads(REPORT_PATH.read_text(encoding="utf-8")), "case_04")
    assert row["status"] == "REJECTED"
    assert any(f["kind"] == "CFL_BREACH" for f in row["findings"])

    shutil.copy(VERIFIER_DIR / "case_04_clean.json", FIXTURE_DIR / "case_04.json")
    _assert_byte_identical_rerun("clean")


@pytest.fixture(scope="module")
def report() -> dict[str, Any]:
    assert REPORT_PATH.is_file(), f"missing {REPORT_PATH}"
    return json.loads(REPORT_PATH.read_text(encoding="utf-8"))


def test_report_contract_immutability(report: dict[str, Any]) -> None:
    """Manifest order immutability schema keys and compact JSON wire format."""
    expected_ids = [f"case_{i:02d}" for i in range(1, 21)]
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    assert manifest["cases"] == expected_ids
    assert [row["case_id"] for row in report["cases"]] == expected_ids
    for rel, digest in IMMUTABLE_SHA256.items():
        assert _sha256_file(APP_DIR / rel) == digest, f"modified {rel}"
    raw = REPORT_PATH.read_bytes()
    assert raw.endswith(b"\n") and b": " not in raw and b", " not in raw
    assert json.loads(raw.decode("utf-8")) == report
    assert REPORT_FIRST.is_file() and raw == REPORT_FIRST.read_bytes()


def test_round_steps_and_point_eight_damper(report: dict[str, Any]) -> None:
    """case_11 round/floor path stores 0.8*0.375=0.3 damped analytic with steps under min."""
    row = _case_row(report, "case_11")
    assert row["steps_taken"] == 6
    assert row["steps_taken"] < 10
    assert any(f["kind"] == "UNDER_RESOLVED" for f in row["findings"])
    assert row["growth_analytic"] == pytest.approx(0.3, abs=1e-12)
    assert row["growth_analytic"] != pytest.approx(0.25, abs=1e-6)
    assert row["growth_analytic"] != pytest.approx(0.375, abs=1e-6)


def test_inverted_ref_over_cfl_dissip(report: dict[str, Any]) -> None:
    """case_06 uses ref/cfl scale: LF 0.01 and UW 0.01220703125; preferred is higher-error upwind."""
    row = _case_row(report, "case_06")
    assert row["status"] == "UNSTABLE"
    assert row["growth_primary"] == pytest.approx(row["growth_analytic"] - 0.01, abs=1e-12)
    assert row["growth_secondary"] == pytest.approx(row["growth_analytic"] - 0.01220703125, abs=1e-12)
    assert row["preferred_scheme"] == "upwind"
    # Forward cfl/ref would not match these inverted magnitudes.
    assert row["growth_primary"] != pytest.approx(row["growth_analytic"] - 0.2048, abs=1e-4)


def test_prefer_higher_abs_error(report: dict[str, Any]) -> None:
    """Preferred scheme is the larger abs error versus analytic case_06 and case_12."""
    row6 = _case_row(report, "case_06")
    assert abs(row6["growth_secondary"] - row6["growth_analytic"]) > abs(
        row6["growth_primary"] - row6["growth_analytic"]
    )
    assert row6["preferred_scheme"] == "upwind"
    row12 = _case_row(report, "case_12")
    assert row12["preferred_scheme"] == "upwind"
    miss = next(f for f in row12["findings"] if f["kind"] == "GROWTH_MISS")
    assert float(miss["detail"]) == pytest.approx(0.018221574344023272, abs=1e-9)


def test_rms_l2_not_linf(report: dict[str, Any]) -> None:
    """case_12 growth_l2_err is dual RMS ~0.01585, not max-abs 0.01822."""
    row = _case_row(report, "case_12")
    expected = math.sqrt(0.5 * (0.018221574344023272**2 + 0.013061224489795853**2))
    assert row["growth_l2_err"] == pytest.approx(expected, abs=1e-12)
    assert row["growth_l2_err"] != pytest.approx(0.018221574344023272, abs=1e-6)


def test_reject_zeros_growth_analytic(report: dict[str, Any]) -> None:
    """Strict CFL reject zeros marched growths and growth_analytic case_04."""
    row = _case_row(report, "case_04")
    assert row["cfl_used"] == pytest.approx(0.95)
    assert row["status"] == "REJECTED"
    assert row["preferred_scheme"] == ""
    assert row["growth_analytic"] == pytest.approx(0.0, abs=1e-15)
    assert row["growth_primary"] == pytest.approx(0.0, abs=1e-15)
    assert row["findings"][0]["kind"] == "CFL_BREACH"
    assert not any(f["kind"] in SOFT_KINDS for f in row["findings"])


def test_stable_preferred_primary_and_linear_ri(report: dict[str, Any]) -> None:
    """case_01 STABLE with linear ri 1.2 and preferred==primary; case_18 stays TRANSITIONAL."""
    row = _case_row(report, "case_01")
    assert row["status"] == "STABLE"
    assert row["findings"] == []
    assert row["preferred_scheme"] == "upwind"
    assert row["richardson"] == pytest.approx(1.2, abs=1e-12)
    assert row["richardson"] != pytest.approx(0.36, abs=1e-6)
    row18 = _case_row(report, "case_18")
    assert row18["findings"] == []
    assert row18["preferred_scheme"] == "upwind"
    assert row18["preferred_scheme"] != "lax_friedrichs"
    assert row18["status"] == "TRANSITIONAL"


def test_ri_crit_override_keeps_full_analytic(report: dict[str, Any]) -> None:
    """Resolved case_08 uses policy_overrides ri_crit 0.08 and undamped analytic 0.1."""
    row = _case_row(report, "case_08")
    assert row["steps_taken"] >= 8
    assert row["ri_crit"] == pytest.approx(0.08)
    assert row["growth_analytic"] == pytest.approx(0.1, abs=1e-12)


def test_growth_identity_after_damper(report: dict[str, Any]) -> None:
    """Marched growth equals stored 0.8-damped analytic minus inverted dissip case_11."""
    row = _case_row(report, "case_11")
    assert row["growth_analytic"] == pytest.approx(0.3, abs=1e-12)
    assert row["growth_primary"] == pytest.approx(0.3 - 0.03160493827160494, abs=1e-12)
    assert row["growth_secondary"] == pytest.approx(0.3 - 0.06858710562414268, abs=1e-12)


def test_dual_cap_transitional_case_17(report: dict[str, Any]) -> None:
    """Primary above cap and secondary at/below cap yields TRANSITIONAL case_17."""
    row = _case_row(report, "case_17")
    assert row["richardson"] < row["ri_crit"]
    assert row["growth_primary"] > 0.0185
    assert row["growth_secondary"] <= 0.0185
    assert row["status"] == "TRANSITIONAL"
