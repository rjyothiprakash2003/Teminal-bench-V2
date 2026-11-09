"""Hard SOC threat hunt admission verifier (v10 organic boost + WATCH investigations)."""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

REPORT_PATH = Path("/app/build/threat_admission_report.json")
REPORT_FIRST = Path("/logs/verifier/report_first.json")
VERIFIER_DIR = Path("/logs/verifier")
FIXTURE_DIR = Path("/app/hunt_captures")
CATALOG_PATH = FIXTURE_DIR / "catalog.json"
CONTRACT_PATH = Path("/app/detect_policy/threat_admission_contract.json")
APP_DIR = Path("/app")

IMMUTABLE_SHA256: dict[str, str] = {
    "Makefile": "6db2e3fd0ccf4948688c4552cd17ab0eac2a0effdfe2f4c005c12efd3d98cc62",
    "go.mod": "9763d5fa66646d2748d49ebae91c9f7ce466687f367d7e474f4855c878bb29d6",
    "detect_policy/threat_admission_contract.json": (
        "5c470e17e87dedf9877a1b2d9deeca8f547bf04a58d59828f397073f36c0de9c"
    ),
    "hunt_captures/catalog.json": "b332629b9425b0f9ea4b86db29dc627076210d80521b97f2a4ebb0bbdc24eb1a",
    "hunt_captures/window_01.json": "e36ec473308140b2b90758b351af8b44827853c00cf0b2e85ca0dadbc76348d1",
    "hunt_captures/window_02.json": "98db81cac4af3c31182bc582ed00fc361cdd5a14f00c3415957076827b10bcd9",
    "hunt_captures/window_03.json": "bfee340b347f685402d0cf5a2d9a06f6216a93b8c79c4d5f4ae60287a2be8389",
    "hunt_captures/window_04.json": "37873a44269272a38769879eb3f45fa7d18d4dcd1e67b1dff9344cf817ef2470",
    "hunt_captures/window_05.json": "1e8705fe216cace530640af588bca55e44897bdd1c21a61d639a18d65e3f04d9",
    "hunt_captures/window_06.json": "467c702923e99c355a6601b14f8e0f0723c54896d5a666e5e88e2c35081cbff8",
    "hunt_captures/window_07.json": "90c099f87c660110dbd6aacf6d4d01fd360d1bfe0944d8294d2e974eb5c56067",
    "hunt_captures/window_08.json": "62087edd01e4cb759af7278eefb1d7544f6df749d6724d4a643395210d26716b",
    "hunt_captures/window_09.json": "2898d2f9dca256c90798413f37222abd276cfde3d6e731d07266ed0bb8409b2b",
    "hunt_captures/window_10.json": "093a1e1a7325549cc1ce2014bd2ca3777d6052f9f8b75c266afc284cd72ea2e6",
    "hunt_captures/window_11.json": "09a5c111bb3d12ea796409ade79cab6348ac54285c54b4863796fea3420a9bab",
    "hunt_captures/window_12.json": "1bff5693ae6aa11445ab27a368c973927ed8845d16b8a26b78f2eee1c03bc6a4",
    "hunt_captures/window_13.json": "02057ef8d9ed102a07e79db80ee1c687aca6c2d4d1ae31b7c135624fb355975e",
    "hunt_captures/window_14.json": "b8cf67d62cd38ebc153fbe47ee217ac85d5fb28ca236d981aff89a7188cb431a",
    "hunt_captures/window_15.json": "7af482134aaaba1d39ce756ff602a6366e04a9e35d74c210b1953f994cea8ee0",
    "hunt_captures/window_16.json": "dd8060e98f8850139a145b81198b1142e94e82850f6c31539a1fb9c6ca9c8769",
    "hunt_captures/window_17.json": "72d74b6693977f5f20434e214ca236e6b1d7d815930d671751cfc3b1ce75db6d",
    "hunt_captures/window_18.json": "668b7a6e015d5e982acf56ef3e3e75a58b742e07e8dddc6196d679b1bc200f18",
    "hunt_captures/window_19.json": "10e54366c06b8a366764e00ef306555253cf74bfb28d6a114e14dd757a0b7034",
    "hunt_captures/window_20.json": "ca65dfde96886aadede06bcb047dec448f26b9b8bc0f9ba0efb0c7abb467fe5a",
}


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


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


def _window(report: dict[str, Any], window_id: str) -> dict[str, Any]:
    for row in report["windows"]:
        if row["window_id"] == window_id:
            return row
    raise KeyError(window_id)


def _host(row: dict[str, Any], host_id: str) -> dict[str, Any]:
    for h in row["hosts"]:
        if h["host_id"] == host_id:
            return h
    raise KeyError(host_id)


def _inv(row: dict[str, Any], host_id: str) -> dict[str, Any]:
    for inv in row["investigations"]:
        if inv["host_id"] == host_id:
            return inv
    raise KeyError(host_id)


def _load_report() -> dict[str, Any]:
    return json.loads(REPORT_PATH.read_text(encoding="utf-8"))


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def _rebuild(tag: str) -> dict[str, Any]:
    _run_make("build", f"{tag}_build.log")
    _run_make("run", f"{tag}_run.log")
    return _load_report()


@pytest.fixture(scope="session", autouse=True)
def _verifier_grading_setup() -> None:
    VERIFIER_DIR.mkdir(parents=True, exist_ok=True)
    w3 = FIXTURE_DIR / "window_03.json"
    backup = VERIFIER_DIR / "window_03.backup.json"
    shutil.copyfile(w3, backup)
    data = json.loads(w3.read_text(encoding="utf-8"))
    data["hosts"][0]["features"]["flow_bytes"]["obs"] = data["hosts"][0]["features"]["flow_bytes"][
        "mean"
    ]
    _write_json(w3, data)
    mutated = _rebuild("mutate_clean")
    assert _host(_window(mutated, "window_03"), "WS-C")["verdict"] == "CLEAN"
    shutil.copyfile(backup, w3)
    first = _rebuild("first")
    shutil.copyfile(REPORT_PATH, REPORT_FIRST)
    second = _rebuild("second")
    assert REPORT_PATH.read_bytes() == REPORT_FIRST.read_bytes()
    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)


@pytest.fixture(scope="module")
def report() -> dict[str, Any]:
    return _load_report()


def test_report_contract_immutability(report: dict[str, Any]) -> None:
    """Catalog order, immutable digests, compact encoding, investigation + boost rules."""
    catalog = json.loads(CATALOG_PATH.read_text(encoding="utf-8"))
    assert [w["window_id"] for w in report["windows"]] == catalog["windows"]
    for rel, digest in IMMUTABLE_SHA256.items():
        assert _sha256_file(APP_DIR / rel) == digest
    contract = json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))
    assert "investigations" in contract["rules"]
    assert "organic_count" in contract["rules"]["boost"]
    assert "risk_medium" in contract["rules"] and "risk_low" in contract["rules"]
    assert contract["risk_values"] == ["HIGH", "MEDIUM", "LOW"]
    assert len(CONTRACT_PATH.read_bytes()) < 9000
    raw = REPORT_PATH.read_bytes()
    assert raw.endswith(b"\n")
    assert b": " not in raw and b", " not in raw
    assert raw == REPORT_FIRST.read_bytes()


def test_investigations_for_watch_and_alert_not_clean(report: dict[str, Any]) -> None:
    """Every WATCH/ALERT host gets an investigation; CLEAN hosts never do."""
    for row in report["windows"]:
        watch_alert = {h["host_id"] for h in row["hosts"] if h["verdict"] in ("WATCH", "ALERT")}
        clean = {h["host_id"] for h in row["hosts"] if h["verdict"] == "CLEAN"}
        inv_hosts = {i["host_id"] for i in row["investigations"]}
        assert inv_hosts == watch_alert
        assert inv_hosts.isdisjoint(clean)
    # Explicit WATCH coverage that agents often skip.
    assert _host(_window(report, "window_12"), "FAR")["verdict"] == "WATCH"
    assert _inv(_window(report, "window_12"), "FAR")["priority"] == 0.519
    assert _host(_window(report, "window_16"), "WS-H")["verdict"] == "WATCH"
    assert _inv(_window(report, "window_16"), "WS-H")["risk"] == "MEDIUM"


def test_organic_boost_excludes_promoted_cluster_members(report: dict[str, Any]) -> None:
    """window_20 size=3 but organic_count=2 => A1 boost 1.3 priority 0.883 not 0.9848."""
    row = _window(report, "window_20")
    assert row["clusters"][0]["size"] == 3
    assert _inv(row, "A1")["priority"] == 0.883
    assert _inv(row, "A1")["priority"] != 0.9848
    assert _inv(row, "Q")["priority"] == 0.4412


def test_maximum_hop_damp_not_minimum(report: dict[str, Any]) -> None:
    """NEAR with hops 1 and 2 paths must use MAXIMUM hops => damp**2."""
    row = _window(report, "window_11")
    assert _inv(row, "NEAR")["priority"] == 0.4204
    assert _inv(row, "BRIDGE")["priority"] == 0.4671
    assert _inv(row, "NEAR")["priority"] != 0.4671


def test_half_open_equal_cost_blocks(report: dict[str, Any]) -> None:
    """cost == contagion_max_cost does not promote FAR (still WATCH + investigation)."""
    row = _window(report, "window_12")
    assert _host(row, "FAR")["verdict"] == "WATCH"
    assert _inv(row, "FAR")["priority"] == 0.519


def test_risk_tiers_low_medium_high(report: dict[str, Any]) -> None:
    """LOW below floor, MEDIUM for WATCH above floor, HIGH only ALERT+gates."""
    assert _inv(_window(report, "window_02"), "WS-B")["risk"] == "LOW"
    assert _inv(_window(report, "window_16"), "WS-H")["risk"] == "MEDIUM"
    assert _inv(_window(report, "window_16"), "WS-H")["risk"] != "HIGH"
    inv15 = _inv(_window(report, "window_15"), "SRV-3")
    assert inv15["risk"] == "HIGH"
    assert inv15["priority"] == 1.374


def test_held_out_seed_z_gate() -> None:
    """policy_overrides contagion_seed_z must apply dynamically."""
    path = FIXTURE_DIR / "window_11.json"
    backup = VERIFIER_DIR / "window_11.seedz.json"
    shutil.copyfile(path, backup)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        data["policy_overrides"] = {"contagion_seed_z": 16}
        _write_json(path, data)
        row = _window(_rebuild("seedz"), "window_11")
        assert _host(row, "NEAR")["verdict"] == "WATCH"
        assert _inv(row, "NEAR")["risk"] in ("LOW", "MEDIUM")
        assert _host(row, "BRIDGE")["verdict"] == "WATCH"
    finally:
        shutil.copyfile(backup, path)
        _rebuild("seedz_restore")


def test_held_out_damp_override_compounds_max_hops() -> None:
    """contagion_damp override compounds by MAXIMUM hops on NEAR."""
    path = FIXTURE_DIR / "window_11.json"
    backup = VERIFIER_DIR / "window_11.damp.json"
    shutil.copyfile(path, backup)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        data["policy_overrides"] = {"contagion_damp": 0.5}
        _write_json(path, data)
        row = _window(_rebuild("damp"), "window_11")
        assert _inv(row, "BRIDGE")["priority"] == 0.2595
        assert _inv(row, "NEAR")["priority"] == 0.1298
    finally:
        shutil.copyfile(backup, path)
        _rebuild("damp_restore")


def test_held_out_clean_peer_excluded_from_cluster_size() -> None:
    """CLEAN peer must not join cluster members or inflate organic boost."""
    path = FIXTURE_DIR / "window_09.json"
    backup = VERIFIER_DIR / "window_09.cleanpeer.json"
    shutil.copyfile(path, backup)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        template = data["hosts"][0]["features"]
        clean = {
            feat: {"mean": sample["mean"], "obs": sample["mean"], "std": sample["std"]}
            for feat, sample in template.items()
        }
        data["hosts"].append(
            {
                "host_id": "WS-J3",
                "role": "workstation",
                "features": clean,
                "peers": ["WS-J1", "WS-J2"],
            }
        )
        data["hosts"][0]["peers"] = ["WS-J2", "WS-J3"]
        data["hosts"][1]["peers"] = ["WS-J1", "WS-J3"]
        _write_json(path, data)
        row = _window(_rebuild("cleanpeer"), "window_09")
        assert row["clusters"][0]["size"] == 2
        assert "WS-J3" not in row["clusters"][0]["members"]
        assert _inv(row, "WS-J1")["priority"] == 0.883
        assert _inv(row, "WS-J1")["priority"] != 0.9848
        assert "WS-J3" not in {i["host_id"] for i in row["investigations"]}
    finally:
        shutil.copyfile(backup, path)
        _rebuild("cleanpeer_restore")


def test_held_out_watch_peer_excluded_from_cluster() -> None:
    """WATCH peer must not join ALERT cluster (seed/quarantine gates blocked via overrides)."""
    path = FIXTURE_DIR / "window_09.json"
    backup = VERIFIER_DIR / "window_09.watchpeer.json"
    shutil.copyfile(path, backup)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        # Block contagion/quarantine promotion so J3 stays WATCH while peer-linked.
        data["policy_overrides"] = {"contagion_seed_z": 100, "quarantine_min": 5}
        template = data["hosts"][0]["features"]
        watch_feat = {
            feat: {"mean": sample["mean"], "obs": sample["mean"], "std": sample["std"]}
            for feat, sample in template.items()
        }
        watch_feat["flow_bytes"] = {"mean": 1000, "obs": 2400, "std": 200}
        data["hosts"].append(
            {
                "host_id": "WS-J3",
                "role": "workstation",
                "features": watch_feat,
                "peers": ["WS-J1", "WS-J2"],
            }
        )
        data["hosts"][0]["peers"] = ["WS-J2", "WS-J3"]
        data["hosts"][1]["peers"] = ["WS-J1", "WS-J3"]
        _write_json(path, data)
        row = _window(_rebuild("watchpeer"), "window_09")
        assert _host(row, "WS-J3")["verdict"] == "WATCH"
        assert _inv(row, "WS-J3")["risk"] == "MEDIUM"
        assert row["clusters"][0]["size"] == 2
        assert "WS-J3" not in row["clusters"][0]["members"]
        assert _inv(row, "WS-J1")["priority"] == 0.883
    finally:
        shutil.copyfile(backup, path)
        _rebuild("watchpeer_restore")


def test_held_out_confidence_floor_forces_low_risk() -> None:
    """Raising confidence_floor keeps WATCH investigation with LOW risk."""
    path = FIXTURE_DIR / "window_04.json"
    backup = VERIFIER_DIR / "window_04.floor.json"
    shutil.copyfile(path, backup)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        data["policy_overrides"] = {"confidence_floor": 0.9}
        _write_json(path, data)
        row = _window(_rebuild("floor"), "window_04")
        assert _host(row, "WS-D")["verdict"] == "WATCH"
        assert _inv(row, "WS-D")["risk"] == "LOW"
        assert _inv(row, "WS-D")["risk"] != "MEDIUM"
    finally:
        shutil.copyfile(backup, path)
        _rebuild("floor_restore")


def test_held_out_quarantine_damp_with_organic_boost() -> None:
    """quarantine_damp override on Q; A1 still uses organic_count=2 boost."""
    path = FIXTURE_DIR / "window_20.json"
    backup = VERIFIER_DIR / "window_20.qdamp.json"
    shutil.copyfile(path, backup)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        data["policy_overrides"] = {"quarantine_damp": 0.5}
        _write_json(path, data)
        row = _window(_rebuild("qdamp"), "window_20")
        assert row["clusters"][0]["size"] == 3
        assert _inv(row, "Q")["priority"] == 0.2595
        assert _inv(row, "A1")["priority"] == 0.883
        assert _inv(row, "A1")["priority"] != 0.9848
    finally:
        shutil.copyfile(backup, path)
        _rebuild("qdamp_restore")


def test_held_out_all_organic_size_three_boost() -> None:
    """Three non-promoted ALERT peers => organic_count=3 boost 1.45 priority 0.9848."""
    path = FIXTURE_DIR / "window_09.json"
    backup = VERIFIER_DIR / "window_09.size3.json"
    shutil.copyfile(path, backup)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        j3_features = {
            feat: dict(sample) for feat, sample in data["hosts"][0]["features"].items()
        }
        data["hosts"].append(
            {
                "host_id": "WS-J3",
                "role": "workstation",
                "features": j3_features,
                "peers": ["WS-J1", "WS-J2"],
            }
        )
        data["hosts"][0]["peers"] = ["WS-J2", "WS-J3"]
        data["hosts"][1]["peers"] = ["WS-J1", "WS-J3"]
        _write_json(path, data)
        row = _window(_rebuild("size3"), "window_09")
        assert row["clusters"][0]["size"] == 3
        assert _inv(row, "WS-J1")["priority"] == 0.9848
        assert _inv(row, "WS-J1")["priority"] != 0.883
    finally:
        shutil.copyfile(backup, path)
        _rebuild("size3_restore")


def test_held_out_peers_only_clustering_ignores_peer_links() -> None:
    """peer_links alone must not form clusters or apply organic boost."""
    path = FIXTURE_DIR / "window_09.json"
    backup = VERIFIER_DIR / "window_09.peersonly.json"
    shutil.copyfile(path, backup)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        for h in data["hosts"]:
            h["peers"] = []
        data["peer_links"] = [
            {"from": "WS-J1", "to": "WS-J2", "cost": 1, "bidirectional": True}
        ]
        _write_json(path, data)
        row = _window(_rebuild("peersonly"), "window_09")
        assert row["clusters"] == []
        assert _inv(row, "WS-J1")["priority"] == 0.6792
    finally:
        shutil.copyfile(backup, path)
        _rebuild("peersonly_restore")
