"""Verification for active learning sampling efficiency validator."""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

REPORT_PATH = Path("/app/build/active_learning_report.json")
REPORT_FIRST = Path("/logs/verifier/report_first.json")
VERIFIER_DIR = Path("/logs/verifier")
FIXTURE_DIR = Path("/app/label_suites")
MANIFEST_PATH = FIXTURE_DIR / "manifest.json"
APP_DIR = Path("/app")

IMMUTABLE_SHA256: dict[str, str] = {
    "Makefile": "c11d91acacaf5be2a9398428097e1da200185b3a09a85fa51beaa5589127e8fc",
    "go.mod": "bd10402f75419882afa31b50d436cc4f75322f233d39fe7633c02647c9e40077",
    "sampling_policy/active_learning_contract.json": "37ffe422976e4aadd0bdf2113c76e4d479f61e9d221baf6aa8511494f1c90000",
    "label_suites/manifest.json": "32eb36629b58ebf1a2da3193edd4870822717063e1dcfe7a5e9959bf8a4d2fdd",
    "label_suites/suite_01.json": "b91fc1f2476470dd426db891d9a4622c82931b899c07a5e33b765f28d7760657",
    "label_suites/suite_02.json": "8c01ee1cbf8cd8d5f836e1d76bd9667eac29ec140b987d76a943e7f2ac518e4a",
    "label_suites/suite_03.json": "31c39d9373d1b5dce2461618b388a598928c8a8be5faf0fc42a47dd079d88f18",
    "label_suites/suite_04.json": "5aa2f521c84ecd095ce9666954c8134ee40ce89e7cc6987c27cf657ced44afdc",
    "label_suites/suite_05.json": "c5e24a2c008891cd25d0e537437c74e8d59fc9eb0353327d5b4d28bffff654e8",
    "label_suites/suite_06.json": "a7e23e0ec75f877e9c9de376a4d0091de6b93ef81b41b0259303efc2ea4503d7",
    "label_suites/suite_07.json": "79ad732c06f3ad7e784ac1b97586616bc4d4d086a9feffb65436075e99a81c0d",
    "label_suites/suite_08.json": "35a3d1899baf6d4fac9e344445e9891fde25035dd7e23ee2525e497b7b34558d",
    "label_suites/suite_09.json": "f1fb34ca0429ea4de6e6379fccd25aad6346d51f699a35bfc76d956238ee414d",
    "label_suites/suite_10.json": "c0ade79d6632f13fcb6110728c938ecba935184daa05a27805ea6da7689ec57c",
    "label_suites/suite_11.json": "ce79fc7ee02405374d4a9a0b2582a5d2635dbc3450a6906760f228855f4c9339",
    "label_suites/suite_12.json": "7ca286c63e0c0a2fb48b30fd967730fccf6090032d483d8ec47dcc2bdf955f23",
    "label_suites/suite_13.json": "869b3100a9409ed350876eeaf336e196f2ae0600c76413a315128c27491e009b",
    "label_suites/suite_14.json": "2ae6752f65059bd5b4f94cd2b95715d7bbdcc82d3c08d895aca63e1987de9f32",
    "label_suites/suite_15.json": "37303d1c3a433f3616f4322984055edcc488582334c996de04f8811ab63d2a3b",
    "label_suites/suite_16.json": "fbbef28dbfa3d3e8d73b027f571c9d57a5f51757a27e7f3405c3973bf54cd7f5",
    "label_suites/suite_17.json": "ff3246708a790d13a177242f68b05ec49030506e185774c0a17d648fba999b77",
    "label_suites/suite_18.json": "701d1736ea73acb92285a1798c415556ffc8d14cf3ad88c9405a7335a9d8b94a",
    "label_suites/suite_19.json": "9d974ae0e465494a5d2b46e170316cf6fd1ea99435cc48c1ffef87d8d1e6d2e2",
    "label_suites/suite_20.json": "06a887964f0eada0dc5faaebbd675e94421eb0ae0e70d706633c374fc3f11ae5",
}


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _perturb_suite_01() -> None:
    path = FIXTURE_DIR / "suite_01.json"
    obj = json.loads(path.read_text(encoding="utf-8"))
    shutil.copy(path, VERIFIER_DIR / "suite_01_clean.json")
    for ev in obj.get("events", []):
        if ev.get("kind") == "RECORD_PROBE":
            ev["accuracy_bps"] = 100
            break
    path.write_text(json.dumps(obj, indent=2) + "\n", encoding="utf-8")


def _perturb_suite_04() -> None:
    path = FIXTURE_DIR / "suite_04.json"
    obj = json.loads(path.read_text(encoding="utf-8"))
    shutil.copy(path, VERIFIER_DIR / "suite_04_clean.json")
    for ev in obj.get("events", []):
        if ev.get("kind") == "PICK_BATCH":
            ev["round"] = 9
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


def _suite_row(report: dict[str, Any], suite_id: str) -> dict[str, Any]:
    for row in report["suites"]:
        if row["suite_id"] == suite_id:
            return row
    raise KeyError(suite_id)


def _assert_suite_finding(
    suite_id: str, kind: str, entity_id: str | None = None, detail: str | None = None
) -> None:
    report = json.loads(REPORT_PATH.read_text(encoding="utf-8"))
    row = _suite_row(report, suite_id)
    finding = next((f for f in row["findings"] if f["kind"] == kind), None)
    assert finding is not None, f"missing {kind} in {suite_id}"
    if entity_id is not None:
        assert finding["entity_id"] == entity_id
    if detail is not None:
        assert finding["detail"] == detail


@pytest.fixture(scope="session", autouse=True)
def _verifier_grading_setup() -> None:
    VERIFIER_DIR.mkdir(parents=True, exist_ok=True)
    for name in ("suite_01_clean.json", "suite_04_clean.json", "report_first.json"):
        (VERIFIER_DIR / name).unlink(missing_ok=True)
    for path in VERIFIER_DIR.glob("*.log"):
        path.unlink()

    _perturb_suite_01()
    REPORT_PATH.unlink(missing_ok=True)
    _run_make("build", "build.log")
    _run_make("run", "run_s01.log")
    shutil.copy(REPORT_PATH, REPORT_FIRST)
    _run_make("run", "run_s01_2.log")
    if REPORT_PATH.read_bytes() != REPORT_FIRST.read_bytes():
        pytest.fail("suite_01 perturbed rerun not byte-identical")

    shutil.copy(VERIFIER_DIR / "suite_01_clean.json", FIXTURE_DIR / "suite_01.json")

    _perturb_suite_04()
    _assert_byte_identical_rerun("s04")
    _assert_suite_finding("suite_04", "STALE_SCORE", "X2", "uncertainty:1")

    shutil.copy(VERIFIER_DIR / "suite_04_clean.json", FIXTURE_DIR / "suite_04.json")
    _assert_byte_identical_rerun("clean")


@pytest.fixture(scope="module")
def report() -> dict[str, Any]:
    assert REPORT_PATH.is_file(), f"missing {REPORT_PATH}"
    return json.loads(REPORT_PATH.read_text(encoding="utf-8"))


def test_report_contract_immutability(report: dict[str, Any]) -> None:
    """Manifest order immutability schema keys and compact JSON wire format."""
    expected_ids = [f"suite_{i:02d}" for i in range(1, 21)]
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    assert manifest["suites"] == expected_ids
    assert [row["suite_id"] for row in report["suites"]] == expected_ids
    for rel, digest in IMMUTABLE_SHA256.items():
        assert _sha256_file(APP_DIR / rel) == digest, f"modified {rel}"
    raw = REPORT_PATH.read_bytes()
    assert raw.endswith(b"\n") and b": " not in raw and b", " not in raw
    canonical = json.dumps(report, separators=(",", ":"), ensure_ascii=False).encode("utf-8") + b"\n"
    assert raw == canonical
    assert REPORT_FIRST.is_file() and raw == REPORT_FIRST.read_bytes()
    for row in report["suites"]:
        for finding in row["findings"]:
            assert "::" in finding["finding_id"]
            parts = finding["finding_id"].split("::")
            assert len(parts) == 3
            assert parts[2].isdigit() and len(parts[2]) == 4


def test_edit_scope_allowlist() -> None:
    """Only allowed top level /app entries may exist."""
    allowed = {
        "samplegate",
        "pickcore",
        "stratops",
        "effimath",
        "build",
        "label_suites",
        "sampling_policy",
        "go.mod",
        "Makefile",
    }
    for entry in APP_DIR.iterdir():
        assert entry.name in allowed, f"unexpected /app/{entry.name}"


def test_seed_labels_excluded_from_metrics(report: dict[str, Any]) -> None:
    """SEED_LABEL must not increment labels_used; query picks alone drive suite_01 metrics."""
    row = _suite_row(report, "suite_01")
    assert row["status"] == "ACCEPTED"
    assert row["strategy"] == "uncertainty"
    assert row["labels_used"] == 2
    assert row["convergence_round"] == 1
    assert row["annotation_efficiency_bps"] == 160000
    assert row["confidence_lo_bps"] == 2733
    assert row["compute_cost_milli"] == 220


def test_negative_efficiency_clamped(report: dict[str, Any]) -> None:
    """When final accuracy is below seed accuracy efficiency must clamp to zero suite_02."""
    row = _suite_row(report, "suite_02")
    assert row["status"] == "ACCEPTED"
    labeled = {s["sample_id"] for s in row["samples"] if s["labeled"]}
    assert "B" in labeled and "C" not in labeled
    assert row["labels_used"] == 1
    assert row["annotation_efficiency_bps"] == 0
    assert row["confidence_lo_bps"] == 700


def test_hybrid_blend_ranking(report: dict[str, Any]) -> None:
    """Tied hybrid_score must break ties by higher diversity then sample_id suite_03."""
    row = _suite_row(report, "suite_03")
    assert row["status"] == "ACCEPTED"
    labeled = {s["sample_id"] for s in row["samples"] if s["labeled"]}
    assert "H3" in labeled
    assert "H2" not in labeled


def test_stale_score(report: dict[str, Any]) -> None:
    """Score age strictly greater than max_score_age_rounds emits STALE_SCORE suite_04."""
    row = _suite_row(report, "suite_04")
    finding = row["findings"][0]
    assert finding["kind"] == "STALE_SCORE"
    assert finding["entity_id"] == "X2"
    assert finding["detail"] == "uncertainty:1"


def test_budget_ignores_seed_consumption(report: dict[str, Any]) -> None:
    """Remaining budget excludes SEED_LABEL so suite_05 emits BUDGET_OVERRUN detail 1."""
    row = _suite_row(report, "suite_05")
    finding = row["findings"][0]
    assert finding["kind"] == "BUDGET_OVERRUN"
    assert finding["entity_id"] == "1"
    assert finding["detail"] == "1"
    assert row["labels_used"] == 0


def test_pick_round_regression(report: dict[str, Any]) -> None:
    """A lower round after an earlier pick emits ROUND_REGRESSION using the prior round."""
    row = _suite_row(report, "suite_06")
    finding = row["findings"][0]
    assert finding["kind"] == "ROUND_REGRESSION"
    assert finding["entity_id"] == "2"
    assert finding["detail"] == "3"
    assert finding["event_seq"] == 8


def test_independent_channel_freshness(report: dict[str, Any]) -> None:
    """Fresh diversity cannot hide stale uncertainty on the top hybrid candidate."""
    row = _suite_row(report, "suite_07")
    finding = row["findings"][0]
    assert finding["kind"] == "STALE_SCORE"
    assert finding["entity_id"] == "F1"
    assert finding["detail"] == "uncertainty:1"
    f1 = next(s for s in row["samples"] if s["sample_id"] == "F1")
    assert f1["score_round"] == 1


def test_hybrid_weight_invalid(report: dict[str, Any]) -> None:
    """Hybrid weights that do not sum to 100 emit HYBRID_WEIGHT_INVALID suite_08."""
    row = _suite_row(report, "suite_08")
    finding = row["findings"][0]
    assert finding["kind"] == "HYBRID_WEIGHT_INVALID"
    assert finding["detail"] == "80:30"


def test_post_label_score_and_dedup(report: dict[str, Any]) -> None:
    """POST_LABEL_SCORE does not bill score_calls; duplicate event_id keeps first uncertainty."""
    row = _suite_row(report, "suite_09")
    kinds = [f["kind"] for f in row["findings"]]
    assert kinds.count("POST_LABEL_SCORE") == 2
    unc = next(f for f in row["findings"] if f["detail"] == "SCORE_UNCERTAINTY")
    div = next(f for f in row["findings"] if f["detail"] == "SCORE_DIVERSITY")
    assert unc["entity_id"] == "D1" and div["entity_id"] == "D1"
    assert row["duplicate_events_skipped"] == 1
    d2 = next(s for s in row["samples"] if s["sample_id"] == "D2")
    assert d2["uncertainty"] == 90
    assert row["labels_used"] == 1
    assert row["compute_cost_milli"] == 110


def test_channel_skew(report: dict[str, Any]) -> None:
    """Channel round gap strictly above max_channel_skew_rounds emits CHANNEL_SKEW suite_10."""
    row = _suite_row(report, "suite_10")
    finding = row["findings"][0]
    assert finding["kind"] == "CHANNEL_SKEW"
    assert finding["entity_id"] == "Y2"
    assert finding["detail"] == "1:5"
    assert finding["event_seq"] == 7
    assert row["labels_used"] == 0


def test_same_sequence_rescore_last_event_wins(report: dict[str, Any]) -> None:
    """Same-seq rescoring replays by event_id and the later Z1 value wins selection."""
    row = _suite_row(report, "suite_11")
    assert row["status"] == "ACCEPTED"
    assert row["findings"] == []
    z1 = next(s for s in row["samples"] if s["sample_id"] == "Z1")
    z2 = next(s for s in row["samples"] if s["sample_id"] == "Z2")
    assert z1["uncertainty"] == 95 and z1["labeled"]
    assert z2["uncertainty"] == 90 and not z2["labeled"]


def test_missing_score_precedes_pool_exhaustion() -> None:
    """An unlabeled sample missing one channel emits SCORE_MISSING rather than POOL_EXHAUSTED."""
    path = FIXTURE_DIR / "suite_11.json"
    clean = path.read_bytes()
    obj = json.loads(clean)
    obj["events"] = [
        ev
        for ev in obj["events"]
        if not (ev.get("kind") == "SCORE_DIVERSITY" and ev.get("sample_id") == "Z1")
    ]
    path.write_text(json.dumps(obj, indent=2) + "\n", encoding="utf-8")
    try:
        _run_make("run", "missing_score_run.log")
        current = json.loads(REPORT_PATH.read_text(encoding="utf-8"))
        row = _suite_row(current, "suite_11")
        assert [f["kind"] for f in row["findings"]] == ["SCORE_MISSING"]
        assert row["findings"][0]["entity_id"] == "Z1"
    finally:
        path.write_bytes(clean)
        _run_make("run", "missing_score_restore.log")


def test_orphan_score(report: dict[str, Any]) -> None:
    """ORPHAN_SCORE uses audit_seq maxSeq+1 with SCORE_UNCERTAINTY detail suite_13."""
    row = _suite_row(report, "suite_13")
    finding = row["findings"][0]
    assert finding["kind"] == "ORPHAN_SCORE"
    assert finding["entity_id"] == "GHOST"
    assert finding["detail"] == "SCORE_UNCERTAINTY"
    assert finding["event_seq"] == 4


def test_strategy_switch_and_pool_exhausted(report: dict[str, Any]) -> None:
    """Strategy change and empty unlabeled pool emit STRATEGY_SWITCH and POOL_EXHAUSTED suite_14."""
    row = _suite_row(report, "suite_14")
    kinds = {f["kind"]: f for f in row["findings"]}
    assert "STRATEGY_SWITCH" in kinds
    assert kinds["STRATEGY_SWITCH"]["entity_id"] == "diversity"
    assert kinds["STRATEGY_SWITCH"]["detail"] == "uncertainty"
    assert "POOL_EXHAUSTED" in kinds


def test_complete_policy_precedence_and_metrics(report: dict[str, Any]) -> None:
    """Overrides beat top-level values; seed labels stay out of labels_used metrics."""
    row = _suite_row(report, "suite_15")
    assert row["status"] == "ACCEPTED"
    assert row["findings"] == []
    labeled = {s["sample_id"] for s in row["samples"] if s["labeled"]}
    assert labeled == {"P0", "P2"}
    assert row["labels_used"] == 1
    assert row["convergence_round"] == 3
    assert row["annotation_efficiency_bps"] == 310000
    assert row["compute_cost_milli"] == 148
    assert row["confidence_lo_bps"] == 2700


def test_cost_exact_boundary_is_allowed(report: dict[str, Any]) -> None:
    """Compute cost equal to the configured maximum remains accepted with seed-excluded labels."""
    row = _suite_row(report, "suite_16")
    assert row["status"] == "ACCEPTED"
    assert row["findings"] == []
    assert row["labels_used"] == 1
    assert row["compute_cost_milli"] == 2000


def test_apply_label_is_idempotent() -> None:
    """Repeated APPLY_LABEL does not add a label or emit PICK_BATCH-only LABEL_LEAK."""
    path = FIXTURE_DIR / "suite_16.json"
    clean = path.read_bytes()
    obj = json.loads(clean)
    obj["events"].insert(
        -1,
        {
            "seq": 8,
            "event_id": "repeat-label",
            "kind": "APPLY_LABEL",
            "sample_id": "K1",
        },
    )
    obj["events"][-1]["seq"] = 9
    path.write_text(json.dumps(obj, indent=2) + "\n", encoding="utf-8")
    try:
        _run_make("run", "idempotent_label_run.log")
        current = json.loads(REPORT_PATH.read_text(encoding="utf-8"))
        row = _suite_row(current, "suite_16")
        assert row["status"] == "ACCEPTED"
        assert row["labels_used"] == 1
        assert row["findings"] == []
    finally:
        path.write_bytes(clean)
        _run_make("run", "idempotent_label_restore.log")


def test_probe_regression_and_stall_round_id(report: dict[str, Any]) -> None:
    """Accuracy drop emits PROBE_REGRESSION and stall entity_id uses last probe round_id."""
    row = _suite_row(report, "suite_17")
    kinds = {f["kind"]: f for f in row["findings"]}
    assert "PROBE_REGRESSION" in kinds
    assert kinds["PROBE_REGRESSION"]["entity_id"] == "12"
    assert kinds["PROBE_REGRESSION"]["detail"] == "7120"
    assert kinds["PROBE_REGRESSION"]["event_seq"] == 6
    assert "CONVERGENCE_STALL" in kinds
    assert kinds["CONVERGENCE_STALL"]["entity_id"] == "12"
    assert kinds["CONVERGENCE_STALL"]["detail"] == "-120"


def test_policy_override_score_age(report: dict[str, Any]) -> None:
    """Large max_score_age_rounds override must allow otherwise stale pick suite_18."""
    row = _suite_row(report, "suite_18")
    assert row["status"] == "ACCEPTED"
    assert row["findings"] == []
    labeled = {s["sample_id"] for s in row["samples"] if s["labeled"]}
    assert "O2" in labeled


def test_uncertainty_lex_tiebreak(report: dict[str, Any]) -> None:
    """Equal uncertainty must pick lexicographically smaller sample_id ALT.A suite_19."""
    row = _suite_row(report, "suite_19")
    assert row["status"] == "ACCEPTED"
    labeled = {s["sample_id"] for s in row["samples"] if s["labeled"]}
    assert "ALT.A" in labeled
    assert "ALT.B" not in labeled


def test_round_gap(report: dict[str, Any]) -> None:
    """Skipping a pick round emits ROUND_GAP with expected next round detail suite_20."""
    row = _suite_row(report, "suite_20")
    finding = next(f for f in row["findings"] if f["kind"] == "ROUND_GAP")
    assert finding["entity_id"] == "3"
    assert finding["detail"] == "2"
    assert finding["event_seq"] == 11
    assert row["labels_used"] == 1
