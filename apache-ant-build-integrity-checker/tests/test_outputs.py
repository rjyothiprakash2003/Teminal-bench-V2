"""Behavioral verification for the Apache Ant release gate binary."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import xml.etree.ElementTree as ET
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

APP = Path("/app")
BINARY = APP / "build" / "antlock"
DECISION = APP / "build" / "ember_gate_decision.json"
WORKCELL = APP / "ember_workcell"
PROJECT = WORKCELL / "ember_pipeline.xml"
CONTRACT = WORKCELL / "ember_integrity_contract.json"
EVIDENCE = WORKCELL / "ember_execution_evidence.json"
LOGS = Path("/logs/verifier")
AGENT_USER = "model"
RUNUSER = Path("/opt/verifier/bin/runuser")

IMMUTABLE_SHA256: dict[str, str] = {
    "go.mod": "321d898f4f4aa74bb5bd76d74387ea0fe88c836e089dd961b5b9f39fa0e18f97",
    "Makefile": "e493ccd405a257c22756af4796e67ae70ae4e4a0c2e5c6d8f5b722b77b205323",
    "antlock/cmd/antlock/main.go": "619276fe49b118592ddbec6ec935719eeb74754ade412755058607457354f4e2",
    "auditmodel/contracts.go": "35af2a548e8ca88f6cf63e8425aac3888430165e4ae1c6252d3fb10b5b0ec6d1",
    "ember_workcell/ember_pipeline.xml": "892b3f051fdac91985817c89edc039db8700d117276290e5ff20ba017b83c4a5",
    "ember_workcell/ember_integrity_contract.json": "f40f1b5d9b22c66c1f56e086ad69734e747f2d6daaa8360bde71360a67a76813",
    "ember_workcell/ember_execution_evidence.json": "fdd619afa772de76361b841b8f15057375ea7e566f7984837bc2d57e6b566a5c",
}

CONTRACT_DATA: dict[str, Any] = json.loads(CONTRACT.read_text())
VIOLATION_CODES: dict[str, str] = CONTRACT_DATA["violation_codes"]
DETAIL_RULES: dict[str, str] = CONTRACT_DATA["detail_rules"]


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _code(rule: str) -> str:
    return VIOLATION_CODES[rule]


def _codes(decision: dict[str, Any]) -> set[str]:
    return {violation["code"] for violation in decision["violations"]}


def _subjects(decision: dict[str, Any], code: str) -> set[str]:
    return {
        violation["subject"]
        for violation in decision["violations"]
        if violation["code"] == code
    }


def _details(decision: dict[str, Any], code: str) -> set[str]:
    return {
        violation["detail"]
        for violation in decision["violations"]
        if violation["code"] == code
    }


def _assert_canonical_order(decision: dict[str, Any]) -> None:
    """Top-level targets, properties, and violations must be ascending canonical order."""
    target_names = [target["name"] for target in decision["targets"]]
    assert target_names == sorted(target_names), "targets must be sorted by name ascending"
    for target in decision["targets"]:
        deps = list(target["dependencies"])
        assert deps == sorted(deps), f"dependencies for {target['name']} must be sorted ascending"
    property_names = [prop["name"] for prop in decision["properties"]]
    assert property_names == sorted(property_names), "properties must be sorted by name ascending"
    violation_keys = [
        (item["code"], item["subject"], item["detail"]) for item in decision["violations"]
    ]
    assert violation_keys == sorted(violation_keys), (
        "violations must be sorted by code, then subject, then detail ascending"
    )


def _run_as_model(argv: list[str], *, cwd: Path = APP) -> subprocess.CompletedProcess[str]:
    """Run submitted make/binary as model so it cannot read root-only /tests."""
    cmd = list(argv)
    if os.geteuid() == 0 and RUNUSER.is_file():
        cmd = [str(RUNUSER), "-u", AGENT_USER, "--", *argv]
    return subprocess.run(
        cmd,
        cwd=cwd,
        capture_output=True,
        text=True,
        env=_agent_env(),
        check=False,
    )


def _prepare_model_workspace() -> None:
    """Clear root-owned build/cache leftovers so the model user can rebuild and overwrite."""
    build = APP / "build"
    if os.geteuid() == 0:
        if build.exists():
            shutil.rmtree(build, ignore_errors=True)
        for path in (
            Path("/home/model/go/cache"),
            Path("/home/model/tmp"),
            Path("/tmp/model-go-cache"),
            Path("/tmp/model-tmp"),
        ):
            if path.exists():
                shutil.rmtree(path, ignore_errors=True)
        build.mkdir(parents=True, exist_ok=True)
        for path in (
            Path("/home/model/go"),
            Path("/home/model/go/cache"),
            Path("/home/model/tmp"),
            Path("/tmp/model-go-cache"),
            Path("/tmp/model-tmp"),
        ):
            path.mkdir(parents=True, exist_ok=True)
        subprocess.run(
            ["chown", "-R", f"{AGENT_USER}:{AGENT_USER}", "/app", "/home/model"],
            check=False,
            capture_output=True,
            text=True,
        )
        subprocess.run(
            ["chown", "-R", f"{AGENT_USER}:{AGENT_USER}", "/tmp/model-go-cache", "/tmp/model-tmp"],
            check=False,
            capture_output=True,
            text=True,
        )
    else:
        build.mkdir(parents=True, exist_ok=True)
        for path in (Path("/home/model/go/cache"), Path("/home/model/tmp")):
            path.mkdir(parents=True, exist_ok=True)


def _agent_env() -> dict[str, str]:
    env = os.environ.copy()
    go_cache = "/tmp/model-go-cache" if Path("/tmp/model-go-cache").is_dir() else "/home/model/go/cache"
    go_tmp = "/tmp/model-tmp" if Path("/tmp/model-tmp").is_dir() else "/home/model/tmp"
    env.update(
        {
            "HOME": "/home/model",
            "GOPATH": "/home/model/go",
            "GOCACHE": go_cache,
            "GOTMPDIR": go_tmp,
            "PATH": "/usr/local/go/bin:/go/bin:/usr/local/bin:/usr/bin:/bin",
        }
    )
    Path(go_cache).mkdir(parents=True, exist_ok=True)
    Path(go_tmp).mkdir(parents=True, exist_ok=True)
    return env


def _world_readable(path: Path) -> None:
    """Ensure model can read verifier-prepared fixtures under tmp paths."""
    path.chmod(0o644)
    for parent in path.parents:
        if parent in {Path("/"), Path("/tmp"), Path("/var"), Path("/private")}:
            break
        try:
            parent.chmod(parent.stat().st_mode | 0o111 | 0o005)
        except OSError:
            break


def _run(
    project: Path,
    contract: Path,
    evidence: Path,
    decision: Path,
) -> tuple[dict[str, Any], bytes]:
    for path in (project, contract, evidence):
        _world_readable(path)
    decision.parent.mkdir(parents=True, exist_ok=True)
    try:
        decision.parent.chmod(decision.parent.stat().st_mode | 0o777)
    except OSError:
        pass
    if decision.exists():
        try:
            if os.geteuid() == 0:
                decision.chmod(0o666)
            decision.unlink()
        except OSError:
            if os.geteuid() == 0:
                subprocess.run(["rm", "-f", str(decision)], check=False)
    proc = _run_as_model(
        [
            str(BINARY),
            "gate",
            "-project",
            str(project),
            "-contract",
            str(contract),
            "-evidence",
            str(evidence),
            "-decision",
            str(decision),
        ]
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    raw = decision.read_bytes()
    parsed = json.loads(raw)
    _assert_canonical_order(parsed)
    return parsed, raw


def _variant(
    tmp_path: Path,
    *,
    project_change: Callable[[ET.Element], None] | None = None,
    evidence_change: Callable[[dict[str, Any]], None] | None = None,
) -> tuple[dict[str, Any], bytes]:
    project = tmp_path / "variant.xml"
    contract = tmp_path / "contract.json"
    evidence = tmp_path / "evidence.json"
    decision = tmp_path / "decision.json"
    shutil.copy(PROJECT, project)
    shutil.copy(CONTRACT, contract)
    shutil.copy(EVIDENCE, evidence)
    if project_change is not None:
        tree = ET.parse(project)
        project_change(tree.getroot())
        tree.write(project, encoding="utf-8", xml_declaration=True)
    if evidence_change is not None:
        data = json.loads(evidence.read_text())
        evidence_change(data)
        evidence.write_text(json.dumps(data), encoding="utf-8")
    return _run(project, contract, evidence, decision)


@pytest.fixture(scope="session", autouse=True)
def _build_and_run() -> None:
    LOGS.mkdir(parents=True, exist_ok=True)
    _prepare_model_workspace()
    proc = _run_as_model(["make", "verify"])
    (LOGS / "antlock-build.log").write_text(proc.stdout + proc.stderr)
    assert proc.returncode == 0, "make verify failed"
    for relative, expected in IMMUTABLE_SHA256.items():
        assert _digest(APP / relative) == expected, f"modified {relative}"
    assert BINARY.is_file()
    raw = DECISION.read_bytes()
    baseline = json.loads(raw)
    assert list(baseline) == ["project", "verdict", "targets", "properties", "violations"]
    assert baseline["verdict"] == "RELEASABLE"
    assert baseline["violations"] == []
    _assert_canonical_order(baseline)
    assert raw.endswith(b"\n") and b": " not in raw and b", " not in raw
    assert DETAIL_RULES["INVALID_SHA256.artifact"] == "artifact"
    assert DETAIL_RULES["INVALID_SHA256.sidecar"] == "sidecar"
    first, raw_first = _run(PROJECT, CONTRACT, EVIDENCE, LOGS / "repeat_a.json")
    second, raw_second = _run(PROJECT, CONTRACT, EVIDENCE, LOGS / "repeat_b.json")
    assert first == second and raw_first == raw_second


def test_01_four_node_scc_marks_every_member(tmp_path: Path) -> None:
    """A four target cycle marks every SCC member, not only the discovery node."""

    def change(root: ET.Element) -> None:
        mapping = {
            "prepare": "generate",
            "generate": "compile",
            "compile": "resources",
            "resources": "prepare",
        }
        for node in root.findall("target"):
            name = node.get("name")
            if name in mapping:
                node.set("depends", mapping[name])

    decision, _ = _variant(tmp_path, project_change=change)
    assert _subjects(decision, _code("target_cycle")) == {
        "compile",
        "generate",
        "prepare",
        "resources",
    }


def test_02_three_property_cycle_marks_full_stack_and_mismatch(tmp_path: Path) -> None:
    """A three name property cycle marks the full stack and still mismatches the contract."""

    def change(data: dict[str, Any]) -> None:
        data["property_layers"][0]["values"].update(
            {
                "release.name": "${archive.name}",
                "archive.name": "${build.epoch}",
                "build.epoch": "${release.name}",
            }
        )

    decision, _ = _variant(tmp_path, evidence_change=change)
    assert {_code("property_cycle"), _code("property_mismatch")} <= _codes(decision)
    assert {"archive.name", "build.epoch", "release.name"} <= _subjects(
        decision, _code("property_cycle")
    )
    assert "ember-core" in _details(decision, _code("property_mismatch"))


def test_03_duplicate_artifact_cofires_literal_invalid_detail(tmp_path: Path) -> None:
    """A duplicate row keeps digest checks and uses the literal artifact detail token."""

    def change(data: dict[str, Any]) -> None:
        duplicate = dict(data["artifacts"][0])
        duplicate["sha256"] = "A" * 64
        data["artifacts"].append(duplicate)

    decision, _ = _variant(tmp_path, evidence_change=change)
    assert {
        _code("duplicate_artifact"),
        _code("invalid_sha256"),
        _code("checksum_mismatch"),
    } <= _codes(decision)
    assert DETAIL_RULES["INVALID_SHA256.artifact"] in _details(decision, _code("invalid_sha256"))
    assert "dist/ember-core.jar" not in _details(decision, _code("invalid_sha256"))


def test_04_duplicate_platform_still_path_compares_and_orders(tmp_path: Path) -> None:
    """Duplicate OS lanes still path compare content and still flag unsorted entries."""

    def change(data: dict[str, Any]) -> None:
        data["packages"][1]["os"] = "linux"
        data["packages"][1]["entries"].reverse()
        for entry in data["packages"][1]["entries"]:
            if entry["path"] == "ember/Main.class":
                entry["sha256"] = "8" * 64

    decision, _ = _variant(tmp_path, evidence_change=change)
    assert {
        _code("duplicate_platform"),
        _code("package_content_mismatch"),
        _code("package_entry_order"),
    } <= _codes(decision)
    assert "ember/Main.class" in _details(decision, _code("package_content_mismatch"))


def test_05_cycle_and_missing_edge_coexist(tmp_path: Path) -> None:
    """Targets in a cycle still receive MISSING_EDGE when a required dependency disappears."""

    def change(root: ET.Element) -> None:
        for node in root.findall("target"):
            if node.get("name") == "prepare":
                node.set("depends", "generate")
            if node.get("name") == "generate":
                node.set("depends", "prepare")
            if node.get("name") == "compile":
                node.set("depends", "prepare")

    decision, _ = _variant(tmp_path, project_change=change)
    assert {_code("target_cycle"), _code("missing_edge")} <= _codes(decision)
    assert {"generate", "prepare"} <= _subjects(decision, _code("target_cycle"))


def test_06_self_loop_with_unknown_dependency(tmp_path: Path) -> None:
    """A self edge and an unknown dependency on the same target both fire."""

    def change(root: ET.Element) -> None:
        node = next(node for node in root.findall("target") if node.get("name") == "resources")
        node.set("depends", "resources, ghost")

    decision, _ = _variant(tmp_path, project_change=change)
    assert {_code("target_cycle"), _code("unknown_dependency")} <= _codes(decision)
    assert _subjects(decision, _code("target_cycle")) == {"resources"}


def test_07_incremental_rebuild_and_output_drift_both_fire(tmp_path: Path) -> None:
    """Unchanged inputs that execute and drift emit both incremental codes."""

    def change(data: dict[str, Any]) -> None:
        run = data["incremental"][0]
        run["executed"] = True
        run["output_after"] = "9" * 64

    decision, _ = _variant(tmp_path, evidence_change=change)
    assert {
        _code("incremental_rebuilt_unchanged"),
        _code("unstable_unchanged_output"),
    } <= _codes(decision)


def test_08_changed_skip_stale_and_missing_case_together(tmp_path: Path) -> None:
    """Changed skip or stale codes coexist with missing case coverage on another target."""

    def change(data: dict[str, Any]) -> None:
        run = data["incremental"][1]
        run["executed"] = False
        run["output_after"] = run["output_before"]
        data["incremental"] = [
            item
            for item in data["incremental"]
            if not (item["target"] == "package" and item["input_before"] != item["input_after"])
        ]

    decision, _ = _variant(tmp_path, evidence_change=change)
    assert {
        _code("incremental_skipped_changed"),
        _code("stale_changed_output"),
        _code("missing_incremental_case"),
    } <= _codes(decision)
    assert "changed" in _details(decision, _code("missing_incremental_case"))


def test_09_invalid_sidecar_literal_and_checksum_cofire(tmp_path: Path) -> None:
    """Bad sidecar syntax uses the literal sidecar detail and still checksum mismatches."""

    def change(data: dict[str, Any]) -> None:
        data["artifacts"][0]["sidecar_sha256"] = "ZZ" + ("1" * 62)

    decision, _ = _variant(tmp_path, evidence_change=change)
    assert {_code("invalid_sha256"), _code("checksum_mismatch")} <= _codes(decision)
    assert DETAIL_RULES["INVALID_SHA256.sidecar"] in _details(decision, _code("invalid_sha256"))
    assert "dist/ember-core.jar" not in _details(decision, _code("invalid_sha256"))


def test_10_unresolved_property_still_emits_mismatch(tmp_path: Path) -> None:
    """Unresolved expansion leaves the required property mismatched as well."""

    def change(data: dict[str, Any]) -> None:
        data["property_layers"][0]["values"]["release.name"] = "${missing.name}"

    decision, _ = _variant(tmp_path, evidence_change=change)
    assert {_code("unresolved_property"), _code("property_mismatch")} <= _codes(decision)
    assert "missing.name" in _details(decision, _code("unresolved_property"))


def test_11_producer_mismatch_invalid_artifact_and_checksum(tmp_path: Path) -> None:
    """Producer, invalid artifact digest, and checksum inequality are independent."""

    def change(data: dict[str, Any]) -> None:
        data["artifacts"][0]["producer"] = "compile"
        data["artifacts"][0]["sha256"] = "B" * 64

    decision, _ = _variant(tmp_path, evidence_change=change)
    assert {
        _code("producer_mismatch"),
        _code("invalid_sha256"),
        _code("checksum_mismatch"),
    } <= _codes(decision)
    assert "package" in _details(decision, _code("producer_mismatch"))
    assert DETAIL_RULES["INVALID_SHA256.artifact"] in _details(decision, _code("invalid_sha256"))


def test_12_unique_os_count_with_duplicate_lane(tmp_path: Path) -> None:
    """Two rows on one OS do not satisfy the two distinct platform rule."""

    def change(data: dict[str, Any]) -> None:
        data["packages"] = [data["packages"][0], dict(data["packages"][0])]

    decision, _ = _variant(tmp_path, evidence_change=change)
    assert {_code("duplicate_platform"), _code("insufficient_platforms")} <= _codes(decision)


def test_13_lex_smallest_content_mismatch_detail(tmp_path: Path) -> None:
    """When two shared entry digests drift, detail is the lexicographically smallest path."""

    def change(data: dict[str, Any]) -> None:
        for entry in data["packages"][2]["entries"]:
            if entry["path"] in {"config/default.properties", "ember/Main.class"}:
                entry["sha256"] = "3" * 64

    decision, _ = _variant(tmp_path, evidence_change=change)
    assert _code("package_content_mismatch") in _codes(decision)
    assert _details(decision, _code("package_content_mismatch")) == {"config/default.properties"}


def test_14_archive_invalid_uses_literal_archive_detail(tmp_path: Path) -> None:
    """An invalid package archive digest uses the literal archive detail token."""

    def change(data: dict[str, Any]) -> None:
        data["packages"][1]["archive_sha256"] = "NOT-A-DIGEST"

    decision, _ = _variant(tmp_path, evidence_change=change)
    assert {_code("invalid_sha256"), _code("package_digest_mismatch")} <= _codes(decision)
    assert DETAIL_RULES["INVALID_SHA256.archive"] in _details(decision, _code("invalid_sha256"))


def test_15_unsafe_order_set_and_entry_invalid_digest(tmp_path: Path) -> None:
    """Unsafe paths, order errors, set mismatch, and invalid entry digests all accumulate."""

    def change(data: dict[str, Any]) -> None:
        entries = data["packages"][2]["entries"]
        entries[0]["path"] = "../escape.class"
        entries[0]["sha256"] = "UPPER" + ("0" * 59)
        entries.reverse()

    decision, _ = _variant(tmp_path, evidence_change=change)
    assert {
        _code("unsafe_entry"),
        _code("package_entry_order"),
        _code("package_entry_set_mismatch"),
        _code("invalid_sha256"),
    } <= _codes(decision)
    assert "../escape.class" in _details(decision, _code("invalid_sha256"))


def test_16_timestamp_mode_and_content_by_path(tmp_path: Path) -> None:
    """Metadata and content checks remain path keyed across platforms."""

    def change(data: dict[str, Any]) -> None:
        entry = next(
            item
            for item in data["packages"][2]["entries"]
            if item["path"] == "config/default.properties"
        )
        entry["mtime"] = 946684801
        entry["mode"] = "0755"
        entry["sha256"] = "3" * 64

    decision, _ = _variant(tmp_path, evidence_change=change)
    assert {
        _code("package_timestamp"),
        _code("package_mode"),
        _code("package_content_mismatch"),
    } <= _codes(decision)
    assert "config/default.properties" in _details(decision, _code("package_content_mismatch"))


def test_17_whitespace_duplicate_depends_normalize(tmp_path: Path) -> None:
    """Messy dependency tokens collapse to a unique sorted adjacency list."""

    def change(root: ET.Element) -> None:
        node = next(node for node in root.findall("target") if node.get("name") == "package")
        node.set("depends", " resources, ,compile, resources , compile ")

    decision, _ = _variant(tmp_path, project_change=change)
    package = next(target for target in decision["targets"] if target["name"] == "package")
    assert package["dependencies"] == ["compile", "resources"]
    assert decision["verdict"] == "RELEASABLE"


def test_18_missing_artifact_and_property_damage(tmp_path: Path) -> None:
    """Missing artifacts and unresolved properties accumulate in one blocked decision."""

    def change(data: dict[str, Any]) -> None:
        data["artifacts"] = []
        data["property_layers"][0]["values"]["build.epoch"] = "${missing.epoch}"

    decision, _ = _variant(tmp_path, evidence_change=change)
    assert {
        _code("missing_artifact"),
        _code("unresolved_property"),
        _code("property_mismatch"),
    } <= _codes(decision)


def test_19_graph_and_evidence_failures_are_independent(tmp_path: Path) -> None:
    """Removing a required target coexists with a bad artifact producer."""

    def project_change(root: ET.Element) -> None:
        root.remove(next(node for node in root.findall("target") if node.get("name") == "checksums"))

    def evidence_change(data: dict[str, Any]) -> None:
        data["artifacts"][0]["producer"] = "generate"

    decision, _ = _variant(tmp_path, project_change=project_change, evidence_change=evidence_change)
    assert {_code("missing_target"), _code("producer_mismatch")} <= _codes(decision)


def test_20_reordered_equal_entries_do_not_invent_content_drift(tmp_path: Path) -> None:
    """Equal reordered entries are order violations only; digest drift still fails separately."""

    def change(data: dict[str, Any]) -> None:
        data["packages"][2]["entries"].reverse()
        data["packages"][2]["archive_sha256"] = "a" * 64

    decision, _ = _variant(tmp_path, evidence_change=change)
    assert _code("package_digest_mismatch") in _codes(decision)
    assert _code("package_entry_order") in _codes(decision)
    assert _code("package_content_mismatch") not in _codes(decision)
    assert "linux" in _details(decision, _code("package_digest_mismatch"))
