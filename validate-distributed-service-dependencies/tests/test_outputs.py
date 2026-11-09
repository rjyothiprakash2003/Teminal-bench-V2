"""Verification for pairing ledger soft-hard confidence classifier."""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

REPORT_PATH = Path("/app/build/pairing_class_report.json")
REPORT_FIRST = Path("/logs/verifier/report_first.json")
VERIFIER_DIR = Path("/logs/verifier")
FIXTURE_DIR = Path("/app/score_cases")
MANIFEST_PATH = FIXTURE_DIR / "manifest.json"
APP_DIR = Path("/app")
SCORECTL = Path("/app/build/scorectl")

IMMUTABLE_SHA256: dict[str, str] = {
    "Makefile": "7bef16806fc7225f2a3e04ccfeb6d9da4436d80d17d152ffd8315ff46a5ee457",
    "go.mod": "7bf15c629b6f131d0501aaaf5051962be05f4e43e5f0ae5d621d9a2fe5d829e5",
    "scorelane/pairing_class_contract.json": "38fd73e25a4eb00a644326f945f0f893282f8336015c052d937767fb304b21a4",
    "score_cases/manifest.json": "9d0f3527961f1c63a75f93fcdc852d8243ff149dbfc0ed52171de9da4468e0c4",
    "score_cases/case_01.json": "63a8bfb5b5d191008f8c6fe529478edf7ffef6652e31e997e594803aef885e0b",
    "score_cases/case_02.json": "9ad834a3241b4766b6558d0fca8511b2a16abc1754c9852396d94024a89ed367",
    "score_cases/case_03.json": "89b1809029eb55cc74152fe93557574a33ca1ad206b42577741973d13dbe34b0",
    "score_cases/case_04.json": "0885246122502235d7d0cae066f1826be1e5e0e3ce912273516dc9dc458d9a89",
    "score_cases/case_05.json": "552e06b65dbfcd24b41c753ba438c21fcf27d3a662e9089857ac62840992ccba",
    "score_cases/case_06.json": "05156ecba80ceaccbf25672dd5f367585f7b0d5e0713458f311b631cf36c1325",
    "score_cases/case_07.json": "9afb193bd0ecd315bed308594685c81fa5ccdb71a411d2af475a28eac72cbb87",
    "score_cases/case_08.json": "2898a411ad2e908a631f17b9826157f7bb1ee8c4795c25b9fc7e32e2ad39509d",
    "score_cases/case_09.json": "1334ab12062d413807de3ca81c029454678dfa29e2d159cfd96f02a762bfa385",
    "score_cases/case_10.json": "b81f7a7b43626d716dc0e1ebb55bad6a14ebd5c15879c88bc1e1259c41b0d37c",
    "score_cases/case_11.json": "0ab3c8db2c72e2ab1a08b275f7acb2a68da596171ffdfd5d5ecba0f2220cf26e",
    "score_cases/case_12.json": "1815b2d61ff98ca9b7925329e4596c9abfa75cc16983d9f6725068ea317a98f2",
    "score_cases/case_13.json": "0815839d8489ce3926da37474b622699507eecec885baaf60c9a2c0d2efaaf6a",
    "score_cases/case_14.json": "17ab6d0d9887d3023f0280f8cb4ef8c8537ba76d2102bacfeab2ea679b96485c",
    "score_cases/case_15.json": "d137907c2a75b76b1766034675a4e020c0930d3070b936d4f71cbd08d50078da",
    "score_cases/case_16.json": "e8fa736117a2c06e14e0771a625e2f85e1c51fdb9a3d740d873b1fbc4c44f10b",
    "score_cases/case_17.json": "41a256514bbb692430e13f559328b36b1c8ac7bc4c45dbd92ffe9f0b9eac68f6",
    "score_cases/case_18.json": "a7f11ae9345f69f4941c7b63f5c7f1878e9de76d637f9a8064bd9fab7e0e77ab",
    "score_cases/case_19.json": "535b31664f1f353d34113aaef4cb086cdf21c6196ad5464d04c70f0812381b41",
    "score_cases/case_20.json": "24b5288eefe71244def787b6f37ac0485055a371466356bc53cb5a6541ea96f6",
}


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _perturb_case_01() -> None:
    path = FIXTURE_DIR / "case_01.json"
    obj = json.loads(path.read_text(encoding="utf-8"))
    shutil.copy(path, VERIFIER_DIR / "case_01_clean.json")
    for ev in obj.get("events", []):
        if ev.get("kind") == "OBSERVE_COUPLING" and ev.get("source_id") == "N2":
            ev["channel"] = "heat"
            break
    path.write_text(json.dumps(obj, indent=2) + "\n", encoding="utf-8")


def _perturb_case_20() -> None:
    path = FIXTURE_DIR / "case_20.json"
    obj = json.loads(path.read_text(encoding="utf-8"))
    shutil.copy(path, VERIFIER_DIR / "case_20_clean.json")
    # Inject via policy_overrides so ResolveCase must honor max_fanout_depth.
    obj["policy_overrides"] = {"max_fanout_depth": 1}
    path.write_text(json.dumps(obj, indent=2) + "\n", encoding="utf-8")


def _run_make(target: str, log_name: str) -> None:
    proc = subprocess.run(
        ["make", target],
        cwd=APP_DIR,
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


def _assert_finding(
    case_id: str, kind: str, entity_id: str | None = None, detail: str | None = None
) -> None:
    report = json.loads(REPORT_PATH.read_text(encoding="utf-8"))
    row = _case_row(report, case_id)
    finding = next((f for f in row["findings"] if f["kind"] == kind), None)
    assert finding is not None, f"missing {kind} in {case_id}"
    if entity_id is not None:
        assert finding["entity_id"] == entity_id
    if detail is not None:
        assert finding["detail"] == detail


@pytest.fixture(scope="session", autouse=True)
def _verifier_grading_setup() -> None:
    VERIFIER_DIR.mkdir(parents=True, exist_ok=True)
    for name in ("case_01_clean.json", "case_20_clean.json", "report_first.json"):
        (VERIFIER_DIR / name).unlink(missing_ok=True)
    for path in VERIFIER_DIR.glob("*.log"):
        path.unlink()

    _perturb_case_01()
    REPORT_PATH.unlink(missing_ok=True)
    _run_make("build", "build.log")
    assert SCORECTL.is_file(), "missing /app/build/scorectl Go binary"
    _run_make("run", "run_c01.log")
    shutil.copy(REPORT_PATH, REPORT_FIRST)
    _run_make("run", "run_c01_2.log")
    if REPORT_PATH.read_bytes() != REPORT_FIRST.read_bytes():
        pytest.fail("case_01 perturbed rerun not byte-identical")
    _assert_finding("case_01", "CHANNEL_DRIFT", "N1", "mass>heat")

    shutil.copy(VERIFIER_DIR / "case_01_clean.json", FIXTURE_DIR / "case_01.json")

    _perturb_case_20()
    _assert_byte_identical_rerun("c20")
    _assert_finding("case_20", "FANOUT_DEPTH", "F", "2")

    shutil.copy(VERIFIER_DIR / "case_20_clean.json", FIXTURE_DIR / "case_20.json")
    _assert_byte_identical_rerun("clean")


@pytest.fixture(scope="module")
def report() -> dict[str, Any]:
    assert REPORT_PATH.is_file(), f"missing {REPORT_PATH}"
    assert SCORECTL.is_file(), "missing /app/build/scorectl"
    return json.loads(REPORT_PATH.read_text(encoding="utf-8"))


def test_report_contract_immutability(report: dict[str, Any]) -> None:
    """Manifest order immutability schema keys compact JSON and Go scorectl binary."""
    expected_ids = [f"case_{i:02d}" for i in range(1, 21)]
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    assert manifest["cases"] == expected_ids
    assert [row["case_id"] for row in report["cases"]] == expected_ids
    for rel, digest in IMMUTABLE_SHA256.items():
        assert _sha256_file(APP_DIR / rel) == digest, f"modified {rel}"
    assert SCORECTL.is_file()
    raw = REPORT_PATH.read_bytes()
    assert raw.endswith(b"\n") and b": " not in raw and b", " not in raw
    canonical = json.dumps(report, separators=(",", ":"), ensure_ascii=False).encode("utf-8") + b"\n"
    assert raw == canonical
    assert REPORT_FIRST.is_file() and raw == REPORT_FIRST.read_bytes()


def test_weight_starve_observe_seq_boost(report: dict[str, Any]) -> None:
    """WEIGHT_STARVE uses observe seq, sink/source fields, BOOST_FLUX, and finding_id NNNN=event_seq."""
    row = _case_row(report, "case_07")
    finding = next(f for f in row["findings"] if f["kind"] == "WEIGHT_STARVE")
    assert finding["entity_id"] == "A"
    assert finding["detail"] == "B"
    assert finding["event_seq"] == 4
    assert finding["finding_id"] == "case_07::A::0004"
    assert "WEIGHT_STARVE" not in finding["finding_id"]
    assert any(c["action"] == "BOOST_FLUX" for c in row["corrections"])
    assert row["confidence"] == 28


def test_fanout_ignores_zero_weight(report: dict[str, Any]) -> None:
    """Fanout live graph cuts at weight zero while WEIGHT_STARVE still fires case_19."""
    row = _case_row(report, "case_19")
    assert not any(f["kind"] == "FANOUT_DEPTH" for f in row["findings"])
    starve = next(f for f in row["findings"] if f["kind"] == "WEIGHT_STARVE")
    assert starve["entity_id"] == "C2"
    assert starve["detail"] == "C1"
    assert row["confidence"] == 28


def test_combo_and_mixed_tax(report: dict[str, Any]) -> None:
    """CHANNEL_DRIFT plus WEIGHT_STARVE combo and soft STALE mixed tax case_03."""
    row = _case_row(report, "case_03")
    kinds = {f["kind"] for f in row["findings"]}
    assert "CHANNEL_DRIFT" in kinds and "WEIGHT_STARVE" in kinds and "STALE_COUPLING" in kinds
    assert next(f for f in row["findings"] if f["kind"] == "CHANNEL_DRIFT")["detail"] == "heat>mass"
    assert row["confidence"] == 64
    assert row["status"] == "OUTLIER"


def test_mixed_tax_survives_zero_soft_dampen() -> None:
    """soft_dampen_pct override zero must apply and still subtract mixed tax case_03."""
    path = FIXTURE_DIR / "case_03.json"
    obj = json.loads(path.read_text(encoding="utf-8"))
    shutil.copy(path, VERIFIER_DIR / "case_03_clean.json")
    obj["policy_overrides"] = {"soft_dampen_pct": 0, "min_confidence": 5}
    path.write_text(json.dumps(obj, indent=2) + "\n", encoding="utf-8")
    try:
        REPORT_PATH.unlink(missing_ok=True)
        _run_make("run", "mixed_tax.log")
        report = json.loads(REPORT_PATH.read_text(encoding="utf-8"))
        row = _case_row(report, "case_03")
        assert row["confidence"] == 60
        assert row["status"] == "OUTLIER"
    finally:
        shutil.copy(VERIFIER_DIR / "case_03_clean.json", path)
        REPORT_PATH.unlink(missing_ok=True)
        _run_make("run", "mixed_tax_restore.log")


def test_soft_dampen_zero_override_zeros_soft_only() -> None:
    """policy_overrides soft_dampen_pct zero must zero soft-only orphan confidence case_02."""
    path = FIXTURE_DIR / "case_02.json"
    obj = json.loads(path.read_text(encoding="utf-8"))
    shutil.copy(path, VERIFIER_DIR / "case_02_clean.json")
    obj["policy_overrides"] = {"soft_dampen_pct": 0, "min_confidence": 5}
    path.write_text(json.dumps(obj, indent=2) + "\n", encoding="utf-8")
    try:
        REPORT_PATH.unlink(missing_ok=True)
        _run_make("run", "soft_zero.log")
        report = json.loads(REPORT_PATH.read_text(encoding="utf-8"))
        row = _case_row(report, "case_02")
        assert row["confidence"] == 0
        assert row["status"] == "STABLE"
    finally:
        shutil.copy(VERIFIER_DIR / "case_02_clean.json", path)
        REPORT_PATH.unlink(missing_ok=True)
        _run_make("run", "soft_zero_restore.log")


def test_hard_confidence_immune_to_zero_dampen() -> None:
    """Hard WEIGHT_STARVE confidence stays 28 under soft_dampen_pct zero case_07."""
    path = FIXTURE_DIR / "case_07.json"
    obj = json.loads(path.read_text(encoding="utf-8"))
    shutil.copy(path, VERIFIER_DIR / "case_07_clean.json")
    obj["policy_overrides"] = {"soft_dampen_pct": 0}
    path.write_text(json.dumps(obj, indent=2) + "\n", encoding="utf-8")
    try:
        REPORT_PATH.unlink(missing_ok=True)
        _run_make("run", "hard_immune.log")
        report = json.loads(REPORT_PATH.read_text(encoding="utf-8"))
        row = _case_row(report, "case_07")
        assert row["confidence"] == 28
        assert row["status"] == "REVIEW"
    finally:
        shutil.copy(VERIFIER_DIR / "case_07_clean.json", path)
        REPORT_PATH.unlink(missing_ok=True)
        _run_make("run", "hard_immune_restore.log")


def test_evidence_stack_three_distinct_hard(report: dict[str, Any]) -> None:
    """Evidence stack needs three distinct hard kinds and suppresses mutual case_16."""
    row = _case_row(report, "case_16")
    hard_kinds = {f["kind"] for f in row["findings"] if f["kind"] in {
        "CYCLE_DETECTED", "CHANNEL_DRIFT", "WEIGHT_STARVE", "FANOUT_DEPTH",
        "DEPTH_EXCEEDED", "REQUIRED_UNREACHABLE", "SEED_UNREACHABLE",
    }}
    assert hard_kinds >= {"CYCLE_DETECTED", "CHANNEL_DRIFT", "WEIGHT_STARVE"}
    assert not any(f["kind"] == "MUTUAL_COUPLING" for f in row["findings"])
    assert row["confidence"] == 100


def test_evidence_ignores_repeated_hard_kind(report: dict[str, Any]) -> None:
    """Three WEIGHT_STARVE findings alone must not award evidence stack case_10."""
    row = _case_row(report, "case_10")
    assert len([f for f in row["findings"] if f["kind"] == "WEIGHT_STARVE"]) == 3
    assert row["confidence"] == 84
    # 28*3=84 with no evidence bonus; raw count of 3 must not add +12
    assert row["confidence"] != 96


def test_mutual_suppressed_by_cycle(report: dict[str, Any]) -> None:
    """Bidirectional chord inside a three-site cycle must not emit MUTUAL_COUPLING case_09."""
    row = _case_row(report, "case_09")
    assert any(f["kind"] == "CYCLE_DETECTED" for f in row["findings"])
    assert not any(f["kind"] == "MUTUAL_COUPLING" for f in row["findings"])
    assert row["confidence"] == 40


def test_cycle_includes_zero_weight_edge(report: dict[str, Any]) -> None:
    """CYCLE_DETECTED must include zero-weight edges while WEIGHT_STARVE still fires case_06."""
    row = _case_row(report, "case_06")
    cycle = next(f for f in row["findings"] if f["kind"] == "CYCLE_DETECTED")
    assert cycle["detail"] == "A>B>C>A"
    assert cycle["entity_id"] == "A"
    starve = next(f for f in row["findings"] if f["kind"] == "WEIGHT_STARVE")
    assert starve["entity_id"] == "A"
    assert row["confidence"] == 68


def test_seed_unreachable_mixed_tax(report: dict[str, Any]) -> None:
    """SEED_UNREACHABLE hard plus orphan softs apply mixed tax case_11."""
    row = _case_row(report, "case_11")
    finding = next(f for f in row["findings"] if f["kind"] == "SEED_UNREACHABLE")
    assert finding["finding_id"] == "case_11::ISLAND::0005"
    assert row["confidence"] == 72


def test_asymmetric_cycle_vs_fanout_graphs(report: dict[str, Any]) -> None:
    """Cycle may use weight zero while fanout must not traverse it case_06 and case_19."""
    c06 = _case_row(report, "case_06")
    c19 = _case_row(report, "case_19")
    assert any(f["kind"] == "CYCLE_DETECTED" for f in c06["findings"])
    assert not any(f["kind"] == "FANOUT_DEPTH" for f in c19["findings"])
    assert c06["confidence"] == 68
    assert c19["confidence"] == 28


def test_duplicate_event_id_first_wins(report: dict[str, Any]) -> None:
    """case_15 skips later duplicate event_ids; DUP never registers; first e04 mass keeps CHANNEL_DRIFT."""
    row = _case_row(report, "case_15")
    assert row["duplicate_events_skipped"] == 2
    assert "DUP" not in {s["site_id"] for s in row["sites"]}
    drift = next(f for f in row["findings"] if f["kind"] == "CHANNEL_DRIFT")
    assert drift["detail"] == "heat>mass"


def test_cycle_lex_rotation_still_required(report: dict[str, Any]) -> None:
    """CYCLE_DETECTED detail must be lex-rotated including return; finding_id uses audit seq."""
    row = _case_row(report, "case_05")
    finding = next(f for f in row["findings"] if f["kind"] == "CYCLE_DETECTED")
    assert finding["detail"] == "A>C>B>A"
    assert finding["entity_id"] == finding["detail"].split(">", 1)[0]
    assert finding["event_seq"] == 10
    assert finding["finding_id"] == "case_05::A::0010"


def test_depth_ignores_optional_declared(report: dict[str, Any]) -> None:
    """Optional required=false declared edges must not lengthen DEPTH_EXCEEDED; depth==max stays quiet."""
    row = _case_row(report, "case_14")
    assert not any(f["kind"] == "DEPTH_EXCEEDED" for f in row["findings"])
    assert any(not c["required"] for c in row["declared_couplings"])
    # required path depth is 4 and max_chain_depth is 4: emit only when strictly greater
    assert row["status"] == "STABLE"
    assert row["confidence"] == 0


def test_depth_trips_when_required_strictly_exceeds() -> None:
    """Lowering max_chain_depth via policy_overrides must trip DEPTH on required-only path case_14."""
    path = FIXTURE_DIR / "case_14.json"
    obj = json.loads(path.read_text(encoding="utf-8"))
    shutil.copy(path, VERIFIER_DIR / "case_14_clean.json")
    obj["policy_overrides"] = {"max_chain_depth": 3}
    path.write_text(json.dumps(obj, indent=2) + "\n", encoding="utf-8")
    try:
        REPORT_PATH.unlink(missing_ok=True)
        _run_make("run", "depth_strict.log")
        report = json.loads(REPORT_PATH.read_text(encoding="utf-8"))
        row = _case_row(report, "case_14")
        depth = next(f for f in row["findings"] if f["kind"] == "DEPTH_EXCEEDED")
        assert depth["detail"] == "4"
        # DEPTH 34 + two optional-only STALE softs dampened − mixed tax => 37
        assert any(f["kind"] == "STALE_COUPLING" for f in row["findings"])
        assert row["confidence"] == 37
        assert row["status"] == "REVIEW"
    finally:
        shutil.copy(VERIFIER_DIR / "case_14_clean.json", path)
        REPORT_PATH.unlink(missing_ok=True)
        _run_make("run", "depth_strict_restore.log")


def test_fanout_equals_max_no_trip(report: dict[str, Any]) -> None:
    """Clean case_20 hop equals max_fanout_depth so FANOUT_DEPTH must stay absent."""
    row = _case_row(report, "case_20")
    assert not any(f["kind"] == "FANOUT_DEPTH" for f in row["findings"])
    assert row["status"] == "STABLE"


def test_partial_cycle_cover_keeps_mutual(report: dict[str, Any]) -> None:
    """Mutual with only one site on a cycle must still emit MUTUAL_COUPLING case_13."""
    row = _case_row(report, "case_13")
    mutual = next(f for f in row["findings"] if f["kind"] == "MUTUAL_COUPLING")
    assert mutual["entity_id"] == "A" and mutual["detail"] == "D"
    assert any(f["kind"] == "CYCLE_DETECTED" for f in row["findings"])
    assert row["confidence"] == 46


def test_full_cycle_cover_suppresses_mutual(report: dict[str, Any]) -> None:
    """Both mutual sites on CYCLE_DETECTED detail suppress MUTUAL while keeping CYCLE case_09."""
    row = _case_row(report, "case_09")
    cycle = next(f for f in row["findings"] if f["kind"] == "CYCLE_DETECTED")
    assert cycle["detail"] == "P>Q>R>P"
    assert "P" in cycle["detail"] and "Q" in cycle["detail"]
    assert not any(f["kind"] == "MUTUAL_COUPLING" for f in row["findings"])
    assert any(c["action"] == "BREAK_CYCLE" for c in row["corrections"])


def test_policy_override_max_fanout_trips() -> None:
    """policy_overrides max_fanout_depth must override top-level case_20 field and emit FANOUT."""
    path = FIXTURE_DIR / "case_20.json"
    obj = json.loads(path.read_text(encoding="utf-8"))
    shutil.copy(path, VERIFIER_DIR / "case_20_ov_clean.json")
    assert obj.get("max_fanout_depth") == 2
    obj["policy_overrides"] = {"max_fanout_depth": 1}
    path.write_text(json.dumps(obj, indent=2) + "\n", encoding="utf-8")
    try:
        REPORT_PATH.unlink(missing_ok=True)
        _run_make("run", "fanout_ov.log")
        report = json.loads(REPORT_PATH.read_text(encoding="utf-8"))
        row = _case_row(report, "case_20")
        fan = next(f for f in row["findings"] if f["kind"] == "FANOUT_DEPTH")
        assert fan["entity_id"] == "F" and fan["detail"] == "2"
        assert row["confidence"] == 34
    finally:
        shutil.copy(VERIFIER_DIR / "case_20_ov_clean.json", path)
        REPORT_PATH.unlink(missing_ok=True)
        _run_make("run", "fanout_ov_restore.log")
