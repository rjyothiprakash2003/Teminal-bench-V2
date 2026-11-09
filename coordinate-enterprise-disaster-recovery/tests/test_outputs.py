"""Verification for enterprise disaster recovery drill orchestrator."""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

REPORT_PATH = Path("/app/build/disaster_recovery_report.json")
REPORT_FIRST = Path("/logs/verifier/report_first.json")
VERIFIER_DIR = Path("/logs/verifier")
FIXTURE_DIR = Path("/app/dc_drills")
MANIFEST_PATH = FIXTURE_DIR / "manifest.json"
APP_DIR = Path("/app")

IMMUTABLE_SHA256: dict[str, str] = {
    "Makefile": "8a260b6ba240bedd4ef91f39a8c43bea1501a8da56e5d2e09b2b9289c580cf78",
    "go.mod": "a28ae04f54a55989d2d69caa8c26808f6a296ea46e27f0ca52d2b87f8557ffe6",
    "dr_blueprint/recovery_orchestration_spec.json": "8d86360d0c0d0ccfa5a965a7673068e8e3f1e9813e3700c08d0a81e1e8c7a24c",
    "dc_drills/manifest.json": "ccd7cbf4fdb9875990b1fbb7c80b61231606d2b78892499fd4201ceffd28bcaa",
    "dc_drills/drill_01.json": "dc096f71c7751694165716ceabbb2bb7b7366c49a12907e7da0137d87d7f26e1",
    "dc_drills/drill_02.json": "b2e8eb119d1ee0fbc99e8b350724e68d13ef081f776ab1d82693a4f583e3ab60",
    "dc_drills/drill_03.json": "5f091b9cdd32d8adfea14d1feab09e0aa0c4b2eac8fdf1bfa7b9410c104e9fd9",
    "dc_drills/drill_04.json": "dca5d5252b7a3d81eef2a6363828dd80aefedb14ef3f66c70036f50c16552c07",
    "dc_drills/drill_05.json": "ec957db2582e65d3dff9224e0620722a2f225c6a2726f29c1c3f71c72f09eb20",
    "dc_drills/drill_06.json": "08cc89580666acd6445062508eb74ea07c871a9fe2ca39ae4f951bb6615f49ed",
    "dc_drills/drill_07.json": "13d9af5df9267fde333358f03cea216321a899ca9fae88a087964baca0759295",
    "dc_drills/drill_08.json": "b7188436fd3e66d012c9c01895b2bc7bfdb2b81e817b077f65b3db0a7d59cd81",
    "dc_drills/drill_09.json": "06d5d7e16d214f02f08de3d8bc84af66edd38167409efd6265ee1a30ec56a1ac",
    "dc_drills/drill_10.json": "5188d19f4d7f35709a4e2f517e96cf55ddefa998ef60e67d7a2caf01ef7debd2",
    "dc_drills/drill_11.json": "015718b79e4cbf07a7bfa031a0ab71afdc561a35741ea00fae29760a151b02c5",
    "dc_drills/drill_12.json": "1685ec70f47c533e670917e16093c5eff9c96364f496c7da2fe2aa57e702a56c",
    "dc_drills/drill_13.json": "22a8af010dfeaab4bdfadd85d3f6c35d16db240b9a1d57ca191916fc839335c7",
    "dc_drills/drill_14.json": "b6932b183e38c0bee115bff0ba8f11119c64e7f3ee311c50b5f454668dc3cc68",
    "dc_drills/drill_15.json": "c37a676f68612bc0d3fbf5c7cb2114461228c2416d7d49b46060a753e3e48d52",
    "dc_drills/drill_16.json": "a17cbbd83112f32b3b1c0edb591cead04401cc08bf69c1244ef3b832f384ebea",
    "dc_drills/drill_17.json": "4519a4396333c3063f8285bf46215054b3a944bfdf840501ec858bacdea5aa05",
    "dc_drills/drill_18.json": "f14566d6ed7d0ffcc0dfde6f0a1ae2751c1bbdc81674921f7d63ad91bc52acad",
    "dc_drills/drill_19.json": "2a293e0c34b3d69ad9fa9251ac140bd4973e0376ff5fa279fb6db7ae0899d45d",
    "dc_drills/drill_20.json": "8e26cb8a8eac0fdf3b21d2e64dd699efcc1cbfcbd211bbfbbcb9dd24365659e0",
}


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _perturb_drill_01() -> None:
    path = FIXTURE_DIR / "drill_01.json"
    obj = json.loads(path.read_text(encoding="utf-8"))
    shutil.copy(path, VERIFIER_DIR / "drill_01_clean.json")
    for ev in obj.get("events", []):
        if ev.get("kind") == "DECLARE_SNAPSHOT" and ev.get("snapshot_id") == "SNAP_DB":
            ev["lag_sec"] = 9999
            break
    path.write_text(json.dumps(obj, indent=2) + "\n", encoding="utf-8")


def _perturb_drill_03() -> None:
    path = FIXTURE_DIR / "drill_03.json"
    obj = json.loads(path.read_text(encoding="utf-8"))
    shutil.copy(path, VERIFIER_DIR / "drill_03_clean.json")
    for ev in obj.get("events", []):
        if ev.get("kind") == "DECLARE_SNAPSHOT" and ev.get("snapshot_id") == "SNAP_DB":
            ev["lag_sec"] = 301
            break
    path.write_text(json.dumps(obj, indent=2) + "\n", encoding="utf-8")


def _run_make(target: str, log_name: str) -> None:
    proc = subprocess.run(
        ["make", target], cwd=APP_DIR, capture_output=True, text=True, check=False
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


def _drill_row(report: dict[str, Any], drill_id: str) -> dict[str, Any]:
    for row in report["drills"]:
        if row["drill_id"] == drill_id:
            return row
    raise KeyError(drill_id)


def _assert_drill_finding(
    drill_id: str, kind: str, entity_id: str | None = None, detail: str | None = None
) -> None:
    report = json.loads(REPORT_PATH.read_text(encoding="utf-8"))
    row = _drill_row(report, drill_id)
    finding = next((f for f in row["findings"] if f["kind"] == kind), None)
    assert finding is not None, f"missing {kind} in {drill_id}"
    if entity_id is not None:
        assert finding["entity_id"] == entity_id
    if detail is not None:
        assert finding["detail"] == detail


@pytest.fixture(scope="session", autouse=True)
def _verifier_grading_setup() -> None:
    VERIFIER_DIR.mkdir(parents=True, exist_ok=True)
    for name in ("drill_01_clean.json", "drill_03_clean.json", "report_first.json"):
        (VERIFIER_DIR / name).unlink(missing_ok=True)
    for path in VERIFIER_DIR.glob("*.log"):
        path.unlink()

    _perturb_drill_01()
    REPORT_PATH.unlink(missing_ok=True)
    _run_make("build", "build.log")
    _run_make("run", "run_d01.log")
    shutil.copy(REPORT_PATH, REPORT_FIRST)
    _run_make("run", "run_d01_2.log")
    if REPORT_PATH.read_bytes() != REPORT_FIRST.read_bytes():
        pytest.fail("drill_01 perturbed rerun not byte-identical")

    shutil.copy(VERIFIER_DIR / "drill_01_clean.json", FIXTURE_DIR / "drill_01.json")

    _perturb_drill_03()
    _assert_byte_identical_rerun("d03")
    _assert_drill_finding("drill_03", "RPO_BREACH", "SNAP_DB", "0301")

    shutil.copy(VERIFIER_DIR / "drill_03_clean.json", FIXTURE_DIR / "drill_03.json")
    _assert_byte_identical_rerun("clean")


@pytest.fixture(scope="module")
def report() -> dict[str, Any]:
    assert REPORT_PATH.is_file(), f"missing {REPORT_PATH}"
    return json.loads(REPORT_PATH.read_text(encoding="utf-8"))


def test_report_contract_immutability(report: dict[str, Any]) -> None:
    """Manifest order immutability schema keys and compact JSON wire format."""
    expected_ids = [f"drill_{i:02d}" for i in range(1, 21)]
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    assert manifest["drills"] == expected_ids
    assert [row["drill_id"] for row in report["drills"]] == expected_ids
    for rel, digest in IMMUTABLE_SHA256.items():
        assert _sha256_file(APP_DIR / rel) == digest, f"modified {rel}"
    raw = REPORT_PATH.read_bytes()
    assert raw.endswith(b"\n") and b": " not in raw and b", " not in raw
    canonical = json.dumps(report, separators=(",", ":"), ensure_ascii=False).encode("utf-8") + b"\n"
    assert raw == canonical
    assert REPORT_FIRST.is_file() and raw == REPORT_FIRST.read_bytes()
    for row in report["drills"]:
        for finding in row["findings"]:
            assert "::" in finding["finding_id"]
            parts = finding["finding_id"].split("::")
            assert len(parts) == 3
            assert parts[2].isdigit() and len(parts[2]) == 4


def test_edit_scope_allowlist() -> None:
    """Only allowed top level /app entries may exist."""
    allowed = {
        "drgate",
        "wavesync",
        "depgraph",
        "slaedge",
        "build",
        "dc_drills",
        "dr_blueprint",
        "go.mod",
        "Makefile",
    }
    for entry in APP_DIR.iterdir():
        assert entry.name in allowed, f"unexpected /app/{entry.name}"


def test_build_artifact_location() -> None:
    """Binary must live under /app/build/drcoord only."""
    assert not (APP_DIR / "drcoord").exists()
    assert (APP_DIR / "build" / "drcoord").is_file()


def test_happy_path_recovered(report: dict[str, Any]) -> None:
    """Ordered dependency restore with valid snapshots admits RECOVERED drill_01."""
    row = _drill_row(report, "drill_01")
    assert row["status"] == "RECOVERED"
    assert row["findings"] == []
    assert row["duplicate_events_skipped"] == 1
    states = {s["service_id"]: s["state"] for s in row["services"]}
    assert states["svc_db"] == "restored"
    assert states["svc_api"] == "restored"


def test_snapshot_corrupt(report: dict[str, Any]) -> None:
    """Wrong restore checksum must emit SNAPSHOT_CORRUPT drill_02."""
    row = _drill_row(report, "drill_02")
    finding = row["findings"][0]
    assert finding["kind"] == "SNAPSHOT_CORRUPT"
    assert finding["entity_id"] == "SNAP_API"
    assert finding["detail"] == "WRONG"


def test_rpo_breach(report: dict[str, Any]) -> None:
    """Snapshot lag above rpo_limit_sec must emit RPO_BREACH drill_03."""
    row = _drill_row(report, "drill_03")
    finding = row["findings"][0]
    assert finding["kind"] == "RPO_BREACH"
    assert finding["entity_id"] == "SNAP_DB"
    assert finding["detail"] == "0500"


def test_rto_breach(report: dict[str, Any]) -> None:
    """Restore duration above rto_limit_sec must emit RTO_BREACH drill_04."""
    row = _drill_row(report, "drill_04")
    finding = row["findings"][0]
    assert finding["kind"] == "RTO_BREACH"
    assert finding["entity_id"] == "svc_db"
    assert finding["detail"] == "1200"


def test_rpo_boundary_exact_limit() -> None:
    """Lag equal to rpo_limit_sec must not emit RPO_BREACH on drill_01."""
    path = FIXTURE_DIR / "drill_01.json"
    clean = json.loads(path.read_text(encoding="utf-8"))
    obj = json.loads(path.read_text(encoding="utf-8"))
    for ev in obj.get("events", []):
        if ev.get("kind") == "DECLARE_SNAPSHOT" and ev.get("snapshot_id") == "SNAP_DB":
            ev["lag_sec"] = 300
    path.write_text(json.dumps(obj, indent=2) + "\n", encoding="utf-8")
    try:
        _run_make("run", "boundary_rpo.log")
        report = json.loads(REPORT_PATH.read_text(encoding="utf-8"))
        row = _drill_row(report, "drill_01")
        assert row["status"] == "RECOVERED"
        assert not any(f["kind"] == "RPO_BREACH" for f in row["findings"])
    finally:
        path.write_text(json.dumps(clean, indent=2) + "\n", encoding="utf-8")
        _run_make("run", "boundary_rpo_restore.log")


def test_dependency_blocked(report: dict[str, Any]) -> None:
    """Restoring dependent before provider must emit DEPENDENCY_BLOCKED drill_05."""
    row = _drill_row(report, "drill_05")
    finding = row["findings"][0]
    assert finding["kind"] == "DEPENDENCY_BLOCKED"
    assert finding["entity_id"] == "svc_api"
    assert finding["detail"] == "svc_db"


def test_dependency_cycle(report: dict[str, Any]) -> None:
    """Cyclic service dependencies must emit DEPENDENCY_CYCLE drill_06."""
    row = _drill_row(report, "drill_06")
    finding = row["findings"][0]
    assert finding["kind"] == "DEPENDENCY_CYCLE"
    assert finding["entity_id"] == "svc_a"
    assert finding["detail"] == "svc_a>svc_b>svc_a"
    assert finding["event_seq"] == 7


def test_wave_capacity_exceeded(report: dict[str, Any]) -> None:
    """Third restore in max_wave_capacity 2 must emit WAVE_CAPACITY_EXCEEDED drill_07."""
    row = _drill_row(report, "drill_07")
    finding = row["findings"][0]
    assert finding["kind"] == "WAVE_CAPACITY_EXCEEDED"
    assert finding["entity_id"] == "W1"
    assert finding["detail"] == "0002"


def test_health_quorum_miss(report: dict[str, Any]) -> None:
    """Ceiling quorum with 2 of 3 healthy must emit HEALTH_QUORUM_MISS drill_08."""
    row = _drill_row(report, "drill_08")
    finding = row["findings"][0]
    assert finding["kind"] == "HEALTH_QUORUM_MISS"
    assert finding["entity_id"] == "drill_08"
    assert finding["detail"] == "0002"


def test_critical_probe_fail(report: dict[str, Any]) -> None:
    """Critical unhealthy probe must emit CRITICAL_PROBE_FAIL drill_09."""
    row = _drill_row(report, "drill_09")
    finding = row["findings"][0]
    assert finding["kind"] == "CRITICAL_PROBE_FAIL"
    assert finding["entity_id"] == "P2"
    assert finding["detail"] == "svc_api"


def test_unmet_provider_lex_smallest(report: dict[str, Any]) -> None:
    """Multiple unmet providers must detail lex smallest id svc_a not svc_z drill_10."""
    row = _drill_row(report, "drill_10")
    finding = row["findings"][0]
    assert finding["kind"] == "DEPENDENCY_BLOCKED"
    assert finding["entity_id"] == "svc_api"
    assert finding["detail"] == "svc_a"


def test_stale_snapshot(report: dict[str, Any]) -> None:
    """Snapshot age above max_snapshot_age_sec must emit STALE_SNAPSHOT drill_11."""
    row = _drill_row(report, "drill_11")
    finding = row["findings"][0]
    assert finding["kind"] == "STALE_SNAPSHOT"
    assert finding["entity_id"] == "S1"
    assert finding["detail"] == "2026-06-01T00:00:00Z"


def test_region_pair_denied(report: dict[str, Any]) -> None:
    """Disallowed failover region pair must emit REGION_PAIR_DENIED drill_12."""
    row = _drill_row(report, "drill_12")
    finding = row["findings"][0]
    assert finding["kind"] == "REGION_PAIR_DENIED"
    assert finding["entity_id"] == "DC_W"
    assert finding["detail"] == "primary>warm"


def test_parallel_conflict_lowercase_state(report: dict[str, Any]) -> None:
    """PARALLEL_CONFLICT detail must be lowercase restored not RECOVERED drill_13."""
    row = _drill_row(report, "drill_13")
    finding = row["findings"][0]
    assert finding["kind"] == "PARALLEL_CONFLICT"
    assert finding["entity_id"] == "s1"
    assert finding["detail"] == "restored"


def test_rollback_direct_not_grandchild(report: dict[str, Any]) -> None:
    """Rollback of db rolls api only; grandchild svc_web stays restored drill_14."""
    row = _drill_row(report, "drill_14")
    assert row["status"] == "ROLLED_BACK"
    states = {s["service_id"]: s["state"] for s in row["services"]}
    assert states["svc_db"] == "rolled_back"
    assert states["svc_api"] == "rolled_back"
    assert states["svc_web"] == "restored"


def test_wave_local_capacity_cap(report: dict[str, Any]) -> None:
    """START_WAVE max_concurrent 1 must beat global 5 and detail 0001 drill_15."""
    row = _drill_row(report, "drill_15")
    finding = row["findings"][0]
    assert finding["kind"] == "WAVE_CAPACITY_EXCEEDED"
    assert finding["entity_id"] == "W1"
    assert finding["detail"] == "0001"


def test_wave_order_violation(report: dict[str, Any]) -> None:
    """Restore into later wave while prior wave empty must emit WAVE_ORDER_VIOLATION drill_16."""
    row = _drill_row(report, "drill_16")
    finding = row["findings"][0]
    assert finding["kind"] == "WAVE_ORDER_VIOLATION"
    assert finding["entity_id"] == "W2"
    assert finding["detail"] == "W1"


def test_rto_boundary_and_metrics(report: dict[str, Any]) -> None:
    """Duration equal to rto_limit_sec must RECOVERED with metrics rto_sec 900 drill_17."""
    row = _drill_row(report, "drill_17")
    assert row["status"] == "RECOVERED"
    assert row["findings"] == []
    assert row["metrics"]["rto_sec"] == 900
    assert row["metrics"]["rpo_sec"] == 120
    assert row["services"][0]["state"] == "restored"


def test_rollback_cascade(report: dict[str, Any]) -> None:
    """EXECUTE_ROLLBACK must mark direct dependents rolled_back lowercase drill_18."""
    row = _drill_row(report, "drill_18")
    assert row["status"] == "ROLLED_BACK"
    states = {s["service_id"]: s["state"] for s in row["services"]}
    assert states["svc_db"] == "rolled_back"
    assert states["svc_api"] == "rolled_back"
    assert any(f["kind"] == "CRITICAL_PROBE_FAIL" for f in row["findings"])


def test_risk_ceiling_hit(report: dict[str, Any]) -> None:
    """Weighted risk above risk_ceiling must emit RISK_CEILING_HIT drill_19."""
    row = _drill_row(report, "drill_19")
    finding = next(f for f in row["findings"] if f["kind"] == "RISK_CEILING_HIT")
    assert finding["entity_id"] == "drill_19"
    assert finding["detail"] == "0003"
    assert row["metrics"]["risk_score"] == 3


def test_string_override_inert(report: dict[str, Any]) -> None:
    """String typed rpo_limit_sec override must stay inert and emit RPO_BREACH drill_20."""
    row = _drill_row(report, "drill_20")
    assert row["status"] == "FAILED"
    finding = row["findings"][0]
    assert finding["kind"] == "RPO_BREACH"
    assert finding["detail"] == "0500"


def test_numeric_override_recovers() -> None:
    """Numeric rpo_limit_sec override 600 must allow lag 500 and RECOVER drill_03 clone."""
    path = FIXTURE_DIR / "drill_03.json"
    clean = json.loads(path.read_text(encoding="utf-8"))
    obj = json.loads(path.read_text(encoding="utf-8"))
    obj["policy_overrides"] = {"rpo_limit_sec": 600}
    path.write_text(json.dumps(obj, indent=2) + "\n", encoding="utf-8")
    try:
        _run_make("run", "numeric_override.log")
        report = json.loads(REPORT_PATH.read_text(encoding="utf-8"))
        row = _drill_row(report, "drill_03")
        assert row["status"] == "RECOVERED"
        assert not any(f["kind"] == "RPO_BREACH" for f in row["findings"])
    finally:
        path.write_text(json.dumps(clean, indent=2) + "\n", encoding="utf-8")
        _run_make("run", "numeric_override_restore.log")
