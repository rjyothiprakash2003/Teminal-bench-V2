"""Verification for realm shadow drift analyzer (Go federation authority replayer)."""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import struct
import subprocess
import zlib
from pathlib import Path
from typing import Any

import pytest

REPORT_PATH = Path("/app/outbox/trust_mesh_audit.json")
REPORT_FIRST = Path("/logs/verifier/report_first.json")
VERIFIER_DIR = Path("/logs/verifier")
TRUSTCORPUS_DIR = Path("/app/trustcorpus")
TRUST_INDEX_PATH = TRUSTCORPUS_DIR / "trust_index.json"
APP_DIR = Path("/app")
BINARY = APP_DIR / "outbox" / "realmshadow"
MAIN_GO = APP_DIR / "svc" / "realmshadow" / "main.go"
MAKEFILE = APP_DIR / "Makefile"

SCENARIO_KEY_ORDER = [
    "scenario_id",
    "status",
    "duplicate_events_skipped",
    "journal",
    "federation_edges",
    "realms",
    "findings",
]

JOURNAL_KEY_ORDER = [
    "format_version",
    "records_total",
    "records_valid",
    "records_rejected",
    "dup_seq_rejects",
    "truncated_tail",
    "payload_bytes",
]

FINDING_KINDS = frozenset(
    {
        "UNVERIFIED_ACTOR",
        "PRIVILEGE_ESCALATION",
        "UNTRUSTED_REALM",
        "DOMAIN_CONTAMINATION",
        "UNKNOWN_TARGET",
        "UNKNOWN_ACTOR",
        "DUPLICATE_REALM",
        "RESURRECTED_REALM",
        "DUPLICATE_FEDERATION",
        "LATERAL_MOVEMENT",
        "RESTRICTED_ESCALATION",
        "FEDERATION_ASYMMETRY",
        "OPEN_AUTHORITY_PATH",
        "ADMIN_UNBOUND",
        "SUSPENDED_REALM",
        "QUARANTINED_REALM",
        "FROZEN_REALM",
        "SEALED_REALM",
        "UNAUTHORIZED_SCOPE_BIND",
    }
)

FINDING_ID_RE = re.compile(r"^[^:]+::[^:]+::\d{4}$")
SHELL_CHAIN_RE = re.compile(r";\s*(?:curl|wget|bash|sh|rm|python3?|cat|exec)\b")
BACKTICK_SHELL_RE = re.compile(r"`(?:curl|wget|bash|sh|rm|python3?|cat|exec)\b")
FILEPATH_JOIN_APP_PATH_RE = re.compile(
    r'filepath\.Join\s*\([^)]*(?:"/app/trustcorpus|"/app/outbox/trust_mesh_audit|federation_trace\.ajn|trust_index\.json)'
)
JOURNAL_OBJ_RE = re.compile(
    r'\{"format_version":\d+,"records_total":\d+,"records_valid":\d+,'
    r'"records_rejected":\d+,"dup_seq_rejects":\d+,"truncated_tail":\d+,'
    r'"payload_bytes":\d+\}'
)
FINDING_KEY_ORDER = [
    "finding_id",
    "entity_id",
    "kind",
    "event_seq",
    "action",
    "detail",
]
FINDING_OBJ_RE = re.compile(
    r'\{"finding_id":"[^"]*","entity_id":"[^"]*","kind":"[^"]*",'
    r'"event_seq":\d+,"action":"(?:[^"\\]|\\.)*","detail":"(?:[^"\\]|\\.)*"\}'
)
SCENARIO_HEAD_RE = re.compile(
    r'\{"scenario_id":"[^"]+","status":"[^"]+",'
    r'"duplicate_events_skipped":\d+,"journal":\{'
)
AUTHORITY_RISK_VALUES = frozenset({"none", "elevated", "critical"})
OUTBOX_DIR = APP_DIR / "outbox"
IMMUTABLE_SHA256: dict[str, str] = {}
SESSION_READY = False
PREFLIGHT_ERROR = ""


def _keys_in_json_object_fragment(fragment: str) -> list[str]:
    return re.findall(r'"([^"]+)":', fragment)


def _assert_raw_objects_use_key_order(raw: bytes, pattern: re.Pattern[str], expected: list[str]) -> None:
    text = raw.decode("utf-8")
    matches = list(pattern.finditer(text))
    assert matches, f"expected at least one object matching {pattern.pattern}"
    for match in matches:
        assert _keys_in_json_object_fragment(match.group(0)) == expected


def _editable_go_source() -> str:
    go_files = sorted((APP_DIR / "svc").rglob("*.go")) + sorted((APP_DIR / "pkg").rglob("*.go"))
    return "\n".join(p.read_text(encoding="utf-8") for p in go_files)


def _has_fixtures_root_literal(code: str) -> bool:
    return '"/app/trustcorpus"' in code or '"/app/trustcorpus/"' in code


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def decode_journal_bytes(data: bytes) -> tuple[dict[str, int], list[dict[str, Any]]]:
    """Decode AJN1 little-endian journal per AJN1_WIRE_FORMAT.md."""
    if len(data) < 8 or data[:4] != b"AJN1":
        raise ValueError("bad magic")
    format_version = struct.unpack_from("<I", data, 4)[0]
    stats: dict[str, int] = {
        "format_version": format_version,
        "records_total": 0,
        "records_valid": 0,
        "records_rejected": 0,
        "dup_seq_rejects": 0,
        "truncated_tail": 0,
        "payload_bytes": 0,
    }
    if format_version != 1:
        raise ValueError("unsupported format_version")
    off = 8
    seen: set[int] = set()
    events: list[dict[str, Any]] = []
    while off < len(data):
        if off + 12 > len(data):
            stats["records_rejected"] += 1
            stats["truncated_tail"] = 1
            break
        record_seq, flags, reserved, plen = struct.unpack_from("<I H H I", data, off)
        off += 12
        stats["records_total"] += 1
        reason = ""
        if reserved != 0:
            reason = "BAD_RESERVED"
        elif flags != 0:
            reason = "BAD_FLAGS"
        elif plen > 4096:
            reason = "LEN_OVERFLOW"
        elif record_seq in seen:
            reason = "DUP_SEQ"
        if reason == "LEN_OVERFLOW":
            if off + plen + 4 <= len(data):
                off += plen + 4
                stats["records_rejected"] += 1
                seen.add(record_seq)
                continue
            stats["records_rejected"] += 1
            stats["truncated_tail"] = 1
            break
        if off + plen + 4 > len(data):
            stats["records_rejected"] += 1
            stats["truncated_tail"] = 1
            break
        payload = data[off : off + plen]
        off += plen
        checksum = struct.unpack_from("<I", data, off)[0]
        off += 4
        if reason == "":
            hdr = struct.pack("<I H H I", record_seq, flags, reserved, plen)
            if zlib.crc32(hdr + payload) & 0xFFFFFFFF != checksum:
                reason = "BAD_CRC"
        seen.add(record_seq)
        if reason:
            stats["records_rejected"] += 1
            if reason == "DUP_SEQ":
                stats["dup_seq_rejects"] += 1
            continue
        try:
            events.append(json.loads(payload.decode("utf-8")))
        except json.JSONDecodeError:
            stats["records_rejected"] += 1
            continue
        stats["records_valid"] += 1
        stats["payload_bytes"] += plen
    return stats, events


def decode_journal(path: Path) -> tuple[dict[str, int], list[dict[str, Any]]]:
    return decode_journal_bytes(path.read_bytes())


def _run_make(target: str, log_name: str) -> None:
    VERIFIER_DIR.mkdir(parents=True, exist_ok=True)
    proc = subprocess.run(
        ["make", target],
        cwd=APP_DIR,
        capture_output=True,
        text=True,
    )
    (VERIFIER_DIR / log_name).write_text(proc.stdout + proc.stderr, encoding="utf-8")
    if proc.returncode != 0:
        pytest.fail(f"make {target} failed; see /logs/verifier/{log_name}")


def _try_make(target: str, log_name: str) -> bool:
    VERIFIER_DIR.mkdir(parents=True, exist_ok=True)
    proc = subprocess.run(
        ["make", target],
        cwd=APP_DIR,
        capture_output=True,
        text=True,
    )
    (VERIFIER_DIR / log_name).write_text(proc.stdout + proc.stderr, encoding="utf-8")
    return proc.returncode == 0


def _require_session_ready() -> None:
    if not SESSION_READY:
        pytest.fail(PREFLIGHT_ERROR or "verifier preflight did not complete (make build/run failed)")


@pytest.fixture(scope="session", autouse=True)
def _verifier_preflight() -> None:
    """Build realmshadow and snapshot first run for byte-identical rerun checks."""
    global SESSION_READY, PREFLIGHT_ERROR
    VERIFIER_DIR.mkdir(parents=True, exist_ok=True)
    REPORT_PATH.unlink(missing_ok=True)
    for path in VERIFIER_DIR.glob("*.log"):
        path.unlink()

    if not _try_make("build", "build.log"):
        PREFLIGHT_ERROR = "make build failed; see /logs/verifier/build.log"
        return
    if not _try_make("run", "run.log"):
        PREFLIGHT_ERROR = "make run failed; see /logs/verifier/run.log"
        return
    if not REPORT_PATH.is_file():
        PREFLIGHT_ERROR = "trust_mesh_audit.json missing after make run"
        return
    shutil.copy(REPORT_PATH, REPORT_FIRST)

    if not _try_make("run", "run2.log"):
        PREFLIGHT_ERROR = "second make run failed; see /logs/verifier/run2.log"
        return
    if REPORT_PATH.read_bytes() != REPORT_FIRST.read_bytes():
        PREFLIGHT_ERROR = "make run not byte-identical across consecutive invocations"
        return

    SESSION_READY = True


@pytest.fixture(scope="session", autouse=True)
def _journal_immutable_hashes(_verifier_preflight: None) -> None:
    """Record SHA-256 of bundled data and docs (including federation_trace.ajn trees)."""
    if IMMUTABLE_SHA256:
        return
    for rel in ("Makefile", "go.mod"):
        IMMUTABLE_SHA256[rel] = _sha256_file(APP_DIR / rel)
    for subdir in ("fedproto", "trustcorpus"):
        root = APP_DIR / subdir
        for path in sorted(root.rglob("*")):
            if path.is_file():
                rel = path.relative_to(APP_DIR).as_posix()
                IMMUTABLE_SHA256[rel] = _sha256_file(path)


def _finding_id(sid: str, entity: str, seq: int) -> str:
    return f"{sid}::{entity}::{seq:04d}"


def _resolve_policy(scenario: dict[str, Any]) -> dict[str, Any]:
    require = bool(scenario.get("require_checkpoint_on_internal", True))
    block = bool(scenario.get("block_partner_to_privileged", True))
    reset_domain = False
    attenuate = False
    open_lex_first = False
    suppress_lateral = False
    audit_priv_asym = False
    prefixes: list[str] = []
    overrides = scenario.get("policy_overrides") or {}
    if isinstance(overrides.get("require_checkpoint_on_internal"), bool):
        require = overrides["require_checkpoint_on_internal"]
    if isinstance(overrides.get("block_partner_to_privileged"), bool):
        block = overrides["block_partner_to_privileged"]
    if isinstance(overrides.get("reset_trust_domain_on_revoke"), bool):
        reset_domain = overrides["reset_trust_domain_on_revoke"]
    if isinstance(overrides.get("attenuate_on_allow"), bool):
        attenuate = overrides["attenuate_on_allow"]
    if isinstance(overrides.get("open_authority_lex_first"), bool):
        open_lex_first = overrides["open_authority_lex_first"]
    if isinstance(overrides.get("suppress_lateral_movement"), bool):
        suppress_lateral = overrides["suppress_lateral_movement"]
    if isinstance(overrides.get("audit_partner_privileged_asymmetry"), bool):
        audit_priv_asym = overrides["audit_partner_privileged_asymmetry"]
    raw_prefixes = overrides.get("require_checkpoint_prefixes")
    if isinstance(raw_prefixes, list):
        prefixes = [str(p) for p in raw_prefixes if isinstance(p, str) and p != ""]
    return {
        "require": require,
        "block": block,
        "prefixes": prefixes,
        "reset_domain": reset_domain,
        "attenuate": attenuate,
        "open_lex_first": open_lex_first,
        "suppress_lateral": suppress_lateral,
        "audit_priv_asym": audit_priv_asym,
    }


def _action_requires_prefix_checkpoint(action: str, prefixes: list[str]) -> bool:
    return any(bool(prefix) and action.startswith(prefix) for prefix in prefixes)


def _authority_risk(tier: str) -> str:
    if tier == "partner":
        return "elevated"
    if tier == "privileged":
        return "critical"
    return "none"


def _event_sort_realm_id(ev: dict[str, Any]) -> str:
    """Sort-key realm_id per TRUST_MESH_REPLAY.md (to_realm / target_realm override)."""
    kind = ev.get("kind", "")
    if kind in ("ALLOW_FEDERATION", "REVOKE_FEDERATION"):
        return ev.get("to_realm") or ev.get("realm_id", "")
    if kind == "AUTHORITY_ACTION":
        return ev.get("target_realm") or ev.get("realm_id", "")
    return ev.get("realm_id", "")


def _sorted_journal_events(sid: str) -> list[dict[str, Any]]:
    _, events = decode_journal(TRUSTCORPUS_DIR / sid / "federation_trace.ajn")
    return sorted(
        events,
        key=lambda e: (e["seq"], _event_sort_realm_id(e), e.get("event_id", "")),
    )


def _authority_action_actions_by_seq(events: list[dict[str, Any]]) -> dict[int, str]:
    return {
        ev["seq"]: ev.get("action", "")
        for ev in events
        if ev.get("kind") == "AUTHORITY_ACTION"
    }


def _events_to_ajn1_blob(events: list[dict[str, Any]]) -> bytes:
    frames: list[bytes] = []
    for idx, ev in enumerate(events, start=1):
        payload = json.dumps(ev, separators=(",", ":")).encode("utf-8")
        frames.append(_pack_ajn1_frame(idx, 0, 0, payload))
    return _pack_ajn1_blob(*frames)


def analyze_scenario(
    scenario: dict[str, Any],
    *,
    journal: tuple[dict[str, int], list[dict[str, Any]]] | None = None,
) -> dict[str, Any]:
    """Independent replay implementing /app/fedproto/TRUST_MESH_REPLAY.md from bundled journal."""
    sid = scenario["scenario_id"]
    if journal is None:
        journal_stats, events = decode_journal(TRUSTCORPUS_DIR / sid / "federation_trace.ajn")
    else:
        journal_stats, events = journal
    pol = _resolve_policy(scenario)
    require_checkpoint = pol["require"]
    block_partner = pol["block"]
    checkpoint_prefixes = pol["prefixes"]
    reset_domain = pol["reset_domain"]
    attenuate = pol["attenuate"]
    open_lex_first = pol["open_lex_first"]
    suppress_lateral = pol["suppress_lateral"]
    audit_priv_asym = pol["audit_priv_asym"]
    realms: dict[str, dict[str, Any]] = {}
    tombstones: set[str] = set()
    edges: set[tuple[str, str]] = set()
    findings: list[dict[str, Any]] = []
    dup_skipped = 0
    seen_event: set[str] = set()
    priv_flagged: set[str] = set()
    max_seq = 0

    events = sorted(
        events,
        key=lambda e: (e["seq"], _event_sort_realm_id(e), e.get("event_id", "")),
    )

    def add_finding(entity: str, kind: str, seq: int, action: str = "", detail: str = "") -> None:
        findings.append(
            {
                "finding_id": _finding_id(sid, entity, seq),
                "entity_id": entity,
                "kind": kind,
                "event_seq": seq,
                "action": action,
                "detail": detail,
            }
        )

    def has_edge(frm: str, to: str) -> bool:
        return (frm, to) in edges

    def first_missing(caps: set[str], propagated: list[str]) -> str:
        missing = sorted(p for p in propagated if p not in caps)
        return missing[0] if missing else ""

    def drop_scope(st: dict[str, Any], scope: str) -> None:
        st["caps"].discard(scope)
        st["scope_via"].pop(scope, None)
        st["scope_expiry"].pop(scope, None)
        st["scope_active_after"].pop(scope, None)
        st["scope_pinned"].pop(scope, None)

    def active_caps(st: dict[str, Any], seq: int) -> set[str]:
        out: set[str] = set()
        for scope in st["caps"]:
            after = int(st["scope_active_after"].get(scope) or 0)
            if after > 0 and not (seq > after):
                continue
            out.add(scope)
        return out

    def cascade_grantor(grantor: str) -> None:
        for st in realms.values():
            drop = [
                scope
                for scope, g in st["scope_via"].items()
                if g == grantor and not st["scope_pinned"].get(scope, False)
            ]
            for scope in drop:
                drop_scope(st, scope)

    def recompute_domain(to: str) -> None:
        st = realms.get(to)
        if st is None:
            return
        st["domain"] = st["registered_domain"]
        st["domain_pinned"] = False
        parents = sorted(frm for frm, tgt in edges if tgt == to and frm in realms)
        for parent in parents:
            parent_domain = realms[parent]["domain"]
            if parent_domain < st["domain"]:
                st["domain"] = parent_domain
        if parents:
            st["domain_pinned"] = True

    def sweep_expiry(seq: int) -> None:
        for st in realms.values():
            drop = [
                scope
                for scope, exp in list(st["scope_expiry"].items())
                if exp > 0 and exp <= seq and not st["scope_pinned"].get(scope, False)
            ]
            for scope in drop:
                drop_scope(st, scope)

    for ev in events:
        seq = ev["seq"]
        max_seq = max(max_seq, seq)
        kind = ev["kind"]
        eid = ev.get("event_id", "")
        if eid:
            if eid in seen_event:
                dup_skipped += 1
                continue
            seen_event.add(eid)
        sweep_expiry(seq)

        if kind == "REGISTER_REALM":
            svc = ev["realm_id"]
            if svc in tombstones:
                add_finding(svc, "RESURRECTED_REALM", seq)
                continue
            if svc in realms:
                add_finding(svc, "DUPLICATE_REALM", seq)
                continue
            domain = ev.get("trust_domain") or "mesh-core"
            realms[svc] = {
                "tier": ev["tier"],
                "registered_domain": domain,
                "domain": domain,
                "domain_pinned": False,
                "caps": set(),
                "suspended": False,
                "quarantined": False,
                "frozen": False,
                "sealed": False,
                "scope_via": {},
                "scope_expiry": {},
                "scope_active_after": {},
                "scope_pinned": {},
            }
            continue

        if kind == "PURGE_REALM":
            svc = ev["realm_id"]
            if svc not in realms:
                add_finding(svc, "UNKNOWN_ACTOR", seq, detail=kind)
                continue
            edges = {(frm, to) for frm, to in edges if frm != svc and to != svc}
            cascade_grantor(svc)
            del realms[svc]
            tombstones.add(svc)
            continue

        if kind == "ALLOW_FEDERATION":
            frm, to = ev["from_realm"], ev["to_realm"]
            if frm == to:
                continue
            if frm not in realms:
                add_finding(frm, "UNKNOWN_ACTOR", seq, detail=kind)
                continue
            if to not in realms:
                add_finding(to, "UNKNOWN_TARGET", seq, detail=kind)
                continue
            if realms[frm]["suspended"]:
                add_finding(frm, "SUSPENDED_REALM", seq, detail="from")
                continue
            if realms[to]["suspended"]:
                add_finding(to, "SUSPENDED_REALM", seq, detail="to")
                continue
            if realms[frm]["quarantined"]:
                add_finding(frm, "QUARANTINED_REALM", seq, detail="from")
                continue
            if realms[to]["quarantined"]:
                add_finding(to, "QUARANTINED_REALM", seq, detail="to")
                continue
            if (frm, to) in edges:
                add_finding(to, "DUPLICATE_FEDERATION", seq, detail=frm)
                continue
            edges.add((frm, to))
            pinned = min(realms[frm]["domain"], realms[to]["registered_domain"])
            realms[to]["domain"] = pinned
            realms[to]["domain_pinned"] = True
            if attenuate:
                child = realms[to]
                parent_caps = realms[frm]["caps"]
                for scope in list(child["caps"]):
                    if child["scope_pinned"].get(scope, False):
                        continue
                    if scope not in parent_caps:
                        drop_scope(child, scope)
            continue

        if kind == "REVOKE_FEDERATION":
            frm, to = ev["from_realm"], ev["to_realm"]
            if frm not in realms:
                add_finding(frm, "UNKNOWN_ACTOR", seq, detail=kind)
                continue
            if to not in realms:
                add_finding(to, "UNKNOWN_TARGET", seq, detail=kind)
                continue
            if (frm, to) not in edges:
                continue
            edges.discard((frm, to))
            st = realms.get(to)
            if st is not None:
                drop = [
                    scope
                    for scope, grantor in st["scope_via"].items()
                    if grantor == frm and not st["scope_pinned"].get(scope, False)
                ]
                for scope in drop:
                    drop_scope(st, scope)
            if reset_domain:
                recompute_domain(to)
            continue

        if kind == "BIND_SCOPE":
            svc = ev["realm_id"]
            if svc not in realms:
                add_finding(svc, "UNKNOWN_ACTOR", seq, detail=kind)
                continue
            if realms[svc]["suspended"]:
                add_finding(svc, "SUSPENDED_REALM", seq, detail="bind")
                continue
            if realms[svc]["quarantined"]:
                add_finding(svc, "QUARANTINED_REALM", seq, detail="bind")
                continue
            if realms[svc]["frozen"]:
                add_finding(svc, "FROZEN_REALM", seq, detail="bind")
                continue
            via_edge = ev.get("via_edge") or ""
            if via_edge:
                if not has_edge(via_edge, svc):
                    add_finding(svc, "UNAUTHORIZED_SCOPE_BIND", seq, detail=via_edge)
                    continue
                if via_edge in realms and (
                    realms[via_edge]["suspended"]
                    or realms[via_edge]["quarantined"]
                    or realms[via_edge]["frozen"]
                ):
                    add_finding(svc, "UNAUTHORIZED_SCOPE_BIND", seq, detail=via_edge)
                    continue
                realms[svc]["caps"].add(ev["scope"])
                realms[svc]["scope_via"][ev["scope"]] = via_edge
            else:
                realms[svc]["caps"].add(ev["scope"])
                realms[svc]["scope_via"][ev["scope"]] = ""
            realms[svc]["scope_pinned"][ev["scope"]] = bool(ev.get("pinned", False))
            exp = int(ev.get("expires_at_seq") or 0)
            if exp > 0:
                realms[svc]["scope_expiry"][ev["scope"]] = exp
            else:
                realms[svc]["scope_expiry"].pop(ev["scope"], None)
            after = int(ev.get("active_after_seq") or 0)
            if after > 0:
                realms[svc]["scope_active_after"][ev["scope"]] = after
            else:
                realms[svc]["scope_active_after"].pop(ev["scope"], None)
            continue

        if kind == "SUSPEND_REALM":
            svc = ev["realm_id"]
            if svc not in realms:
                add_finding(svc, "UNKNOWN_ACTOR", seq, detail=kind)
                continue
            realms[svc]["suspended"] = True
            continue

        if kind == "QUARANTINE_REALM":
            svc = ev["realm_id"]
            if svc not in realms:
                add_finding(svc, "UNKNOWN_ACTOR", seq, detail=kind)
                continue
            realms[svc]["quarantined"] = True
            continue

        if kind == "FREEZE_REALM":
            svc = ev["realm_id"]
            if svc not in realms:
                add_finding(svc, "UNKNOWN_ACTOR", seq, detail=kind)
                continue
            realms[svc]["frozen"] = True
            continue

        if kind == "SEAL_REALM":
            svc = ev["realm_id"]
            if svc not in realms:
                add_finding(svc, "UNKNOWN_ACTOR", seq, detail=kind)
                continue
            realms[svc]["sealed"] = True
            continue

        if kind == "UNSEAL_REALM":
            svc = ev["realm_id"]
            if svc not in realms:
                add_finding(svc, "UNKNOWN_ACTOR", seq, detail=kind)
                continue
            realms[svc]["sealed"] = False
            continue

        if kind == "ROTATE_TRUST_DOMAIN":
            svc = ev["realm_id"]
            if svc not in realms:
                add_finding(svc, "UNKNOWN_ACTOR", seq, detail=kind)
                continue
            domain = ev.get("trust_domain") or "mesh-core"
            realms[svc]["registered_domain"] = domain
            realms[svc]["domain"] = domain
            continue

        if kind == "AUTHORITY_ACTION":
            actor, target = ev["actor_id"], ev["target_realm"]
            action = ev.get("action", "")
            propagated = ev.get("propagated_scopes") or []
            if target not in realms:
                add_finding(target, "UNKNOWN_TARGET", seq, action=action, detail=kind)
                continue
            if actor not in realms:
                add_finding(actor, "UNKNOWN_ACTOR", seq, action=action, detail=kind)
                continue
            if realms[actor]["suspended"]:
                add_finding(actor, "SUSPENDED_REALM", seq, action=action, detail="actor")
                continue
            if realms[target]["suspended"]:
                add_finding(target, "SUSPENDED_REALM", seq, action=action, detail="target")
                continue
            if realms[actor]["frozen"]:
                add_finding(actor, "FROZEN_REALM", seq, action=action, detail="actor")
                continue
            if realms[target]["frozen"]:
                add_finding(target, "FROZEN_REALM", seq, action=action, detail="target")
                continue
            if realms[actor]["sealed"]:
                add_finding(actor, "SEALED_REALM", seq, action=action, detail="actor")
                continue
            if realms[target]["sealed"]:
                add_finding(target, "SEALED_REALM", seq, action=action, detail="target")
                continue
            if not has_edge(actor, target):
                add_finding(target, "UNTRUSTED_REALM", seq, action=action, detail=actor)
                continue
            if realms[actor]["domain"] != realms[target]["domain"]:
                add_finding(target, "DOMAIN_CONTAMINATION", seq, action=action, detail=actor)
                continue
            if (
                block_partner
                and realms[actor]["tier"] == "partner"
                and realms[target]["tier"] == "privileged"
                and len(propagated) == 0
            ):
                add_finding(target, "RESTRICTED_ESCALATION", seq, action=action, detail=actor)
                continue
            if require_checkpoint and realms[target]["tier"] == "internal" and not ev.get("has_checkpoint"):
                add_finding(target, "UNVERIFIED_ACTOR", seq, action=action)
                continue
            if (
                checkpoint_prefixes
                and _action_requires_prefix_checkpoint(action, checkpoint_prefixes)
                and not ev.get("has_checkpoint")
            ):
                add_finding(actor, "UNVERIFIED_ACTOR", seq, action=action)
                continue
            live = active_caps(realms[actor], seq)
            miss_sorted = first_missing(live, propagated)
            if miss_sorted:
                key = f"{actor}::{miss_sorted}"
                if key not in priv_flagged:
                    priv_flagged.add(key)
                    add_finding(actor, "PRIVILEGE_ESCALATION", seq, action=action, detail=miss_sorted)
            if not suppress_lateral:
                orig = ev.get("original_actor") or ""
                if (
                    orig
                    and orig != actor
                    and orig in realms
                    and not realms[orig]["suspended"]
                ):
                    miss_array = next((p for p in propagated if p not in live), "")
                    if miss_array:
                        add_finding(orig, "LATERAL_MOVEMENT", seq, action=action, detail=miss_array)

    audit_seq = max_seq + 1
    mesh_flagged: set[str] = set()
    open_flagged: set[str] = set()

    for frm, to in sorted(edges):
        if frm not in realms or to not in realms:
            continue
        if realms[frm]["tier"] == "partner" and (
            realms[to]["tier"] == "internal"
            or (audit_priv_asym and realms[to]["tier"] == "privileged")
        ):
            mkey = f"{frm}::{to}"
            if mkey not in mesh_flagged and not has_edge(to, frm):
                mesh_flagged.add(mkey)
                add_finding(frm, "FEDERATION_ASYMMETRY", audit_seq, detail=to)

    for realm_id in sorted(realms):
        st = realms[realm_id]
        if st["tier"] != "privileged":
            continue
        if "fed:audit" in st["caps"]:
            continue
        partners = sorted(
            frm
            for frm, to in edges
            if to == realm_id and frm in realms and realms[frm]["tier"] == "partner"
        )
        if partners and realm_id not in open_flagged:
            open_flagged.add(realm_id)
            detail = partners[0] if open_lex_first else partners[-1]
            add_finding(realm_id, "OPEN_AUTHORITY_PATH", audit_seq, detail=detail)

    for realm_id in sorted(realms):
        if realms[realm_id]["tier"] != "privileged":
            continue
        if "fed:admin" in realms[realm_id]["caps"]:
            continue
        if realm_id in open_flagged:
            continue
        add_finding(realm_id, "ADMIN_UNBOUND", audit_seq)

    edge_out = [
        {"from_realm": frm, "to_realm": to}
        for frm, to in sorted(edges)
    ]
    out_realms = [
        {
            "realm_id": realm_id,
            "tier": realms[realm_id]["tier"],
            "bound_scopes": sorted(realms[realm_id]["caps"]),
            "authority_risk": _authority_risk(realms[realm_id]["tier"]),
        }
        for realm_id in sorted(realms)
    ]

    findings.sort(key=lambda f: (f["finding_id"], f["kind"]))
    journal = {k: journal_stats[k] for k in JOURNAL_KEY_ORDER}
    return {
        "scenario_id": sid,
        "status": "VALID" if not findings else "INVALID",
        "duplicate_events_skipped": dup_skipped,
        "journal": journal,
        "federation_edges": edge_out,
        "realms": out_realms,
        "findings": findings,
    }



def _build_report() -> dict[str, Any]:
    manifest = json.loads(TRUST_INDEX_PATH.read_text(encoding="utf-8"))
    return {
        "scenarios": [
            analyze_scenario(json.loads((TRUSTCORPUS_DIR / f"{sid}.json").read_text(encoding="utf-8")))
            for sid in manifest["scenarios"]
        ]
    }


def _scenario_row(report: dict[str, Any], scenario_id: str) -> dict[str, Any]:
    for row in report["scenarios"]:
        if row["scenario_id"] == scenario_id:
            return row
    raise KeyError(scenario_id)


@pytest.fixture(scope="module")
def report() -> dict[str, Any]:
    _require_session_ready()
    assert REPORT_PATH.is_file(), f"missing {REPORT_PATH}"
    return json.loads(REPORT_PATH.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def expected_report() -> dict[str, Any]:
    return _build_report()


def _report_digest(report: dict[str, Any]) -> str:
    payload = json.dumps(report, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _assert_no_json_null(value: Any, path: str = "report") -> None:
    if value is None:
        raise AssertionError(f"null at {path}")
    if isinstance(value, dict):
        for key, item in value.items():
            _assert_no_json_null(item, f"{path}.{key}")
    elif isinstance(value, list):
        for idx, item in enumerate(value):
            _assert_no_json_null(item, f"{path}[{idx}]")


def _assert_schema_sort_order(row: dict[str, Any]) -> None:
    edges = row["federation_edges"]
    assert edges == sorted(edges, key=lambda e: (e["from_realm"], e["to_realm"]))
    svc_ids = [s["realm_id"] for s in row["realms"]]
    assert svc_ids == sorted(svc_ids)
    for svc in row["realms"]:
        assert svc["bound_scopes"] == sorted(svc["bound_scopes"])
    finding_keys = [(f["finding_id"], f["kind"]) for f in row["findings"]]
    assert finding_keys == sorted(finding_keys)


def _sample_register_payload(event_id: str = "e1") -> bytes:
    ev = {
        "seq": 1,
        "event_id": event_id,
        "realm_id": "billing",
        "kind": "REGISTER_REALM",
        "tier": "internal",
    }
    return json.dumps(ev, separators=(",", ":")).encode("utf-8")


def _pack_ajn1_frame(record_seq: int, flags: int, reserved: int, payload: bytes) -> bytes:
    hdr = struct.pack("<I H H I", record_seq, flags, reserved, len(payload))
    crc = struct.pack("<I", zlib.crc32(hdr + payload) & 0xFFFFFFFF)
    return hdr + payload + crc


def _pack_ajn1_blob(*frames: bytes, format_version: int = 1) -> bytes:
    return b"AJN1" + struct.pack("<I", format_version) + b"".join(frames)


def test_full_replay_equivalence_invariant(
    report: dict[str, Any], expected_report: dict[str, Any]
) -> None:
    """Every manifest scenario must match the authority-rules replay with no drift."""
    assert report == expected_report
    kinds = {f["kind"] for row in report["scenarios"] for f in row["findings"]}
    assert kinds == FINDING_KINDS
    assert len(report["scenarios"]) == 62
    assert _report_digest(report) == _report_digest(expected_report)


def test_solution_contract_immutability_and_compact_json(report: dict[str, Any]) -> None:
    """Bundled immutability, manifest order, SCHEMA keys, compact JSON, raw key order, no null."""
    _require_session_ready()
    assert (APP_DIR / "go.mod").read_text(encoding="utf-8").startswith("module realmshadow")
    assert MAIN_GO.is_file(), "entry point must remain /app/svc/realmshadow/main.go"
    assert BINARY.is_file(), "make build must produce /app/outbox/realmshadow"
    assert REPORT_PATH.is_file(), "make run must produce /app/outbox/trust_mesh_audit.json"

    for path in APP_DIR.rglob("*"):
        if not path.is_file():
            continue
        rel = path.relative_to(APP_DIR).as_posix()
        if rel.startswith(("svc/", "pkg/", "outbox/")):
            continue
        assert rel in IMMUTABLE_SHA256, f"untracked path {rel}"
        assert _sha256_file(path) == IMMUTABLE_SHA256[rel], f"modified {rel}"

    expected_ids = [f"realmcase_{i:02d}" for i in range(1, 63)]
    manifest = json.loads(TRUST_INDEX_PATH.read_text(encoding="utf-8"))
    assert manifest["scenarios"] == expected_ids
    assert [row["scenario_id"] for row in report["scenarios"]] == expected_ids

    raw = REPORT_PATH.read_bytes()
    assert raw.startswith(b'{"scenarios":')
    assert list(report.keys()) == ["scenarios"]
    assert raw.endswith(b"\n") and b": " not in raw and b", " not in raw and b"null" not in raw
    canonical = json.dumps(report, separators=(",", ":"), ensure_ascii=False).encode("utf-8") + b"\n"
    assert raw == canonical
    assert REPORT_FIRST.is_file() and raw == REPORT_FIRST.read_bytes()

    text = raw.decode("utf-8").rstrip("\n")
    assert SCENARIO_HEAD_RE.search(text), "scenario objects must use AUDIT_SNAPSHOT_SCHEMA.md key order in raw JSON"
    _assert_raw_objects_use_key_order(raw, JOURNAL_OBJ_RE, JOURNAL_KEY_ORDER)
    if FINDING_OBJ_RE.search(text):
        _assert_raw_objects_use_key_order(raw, FINDING_OBJ_RE, FINDING_KEY_ORDER)

    code = _editable_go_source()
    assert _has_fixtures_root_literal(code)
    assert '"/app/outbox/trust_mesh_audit.json"' in code
    assert FILEPATH_JOIN_APP_PATH_RE.search(code) is None
    assert str(BINARY) == "/app/outbox/realmshadow"
    assert BINARY.is_file() and BINARY.read_bytes()[:4] == b"\x7fELF"
    assert {p.name for p in OUTBOX_DIR.iterdir()} == {"realmshadow", "trust_mesh_audit.json"}

    for row in report["scenarios"]:
        assert list(row.keys()) == SCENARIO_KEY_ORDER
        assert list(row["journal"].keys()) == JOURNAL_KEY_ORDER
        _assert_schema_sort_order(row)
        for finding in row["findings"]:
            assert FINDING_ID_RE.match(finding["finding_id"])
            assert finding["kind"] in FINDING_KINDS
        for svc in row["realms"]:
            assert set(svc.keys()) == {"realm_id", "tier", "bound_scopes", "authority_risk"}
            assert "trust_domain" not in svc
        stats, _ = decode_journal(TRUSTCORPUS_DIR / row["scenario_id"] / "federation_trace.ajn")
        assert row["journal"] == {k: stats[k] for k in JOURNAL_KEY_ORDER}, row["scenario_id"]
    _assert_no_json_null(report)

def test_realmcase_41_last_allow_domain_pin_contaminates_first_parent(
    report: dict[str, Any], expected_report: dict[str, Any]
) -> None:
    """Every ALLOW re-pins leaf from registered_domain; later p_lo pin makes AUTHORITY from p_hi DOMAIN_CONTAMINATION."""
    row = _scenario_row(report, "realmcase_41")
    expected = _scenario_row(expected_report, "realmcase_41")
    assert row == expected
    contam = [f for f in row["findings"] if f["kind"] == "DOMAIN_CONTAMINATION"]
    assert len(contam) == 1
    assert contam[0]["entity_id"] == "leaf"
    assert contam[0]["detail"] == "p_hi"
    assert not any(f["kind"] == "UNTRUSTED_REALM" for f in row["findings"])


def test_realmcase_46_nonempty_missing_scopes_privilege_not_restricted(
    report: dict[str, Any], expected_report: dict[str, Any]
) -> None:
    """Non-empty missing scopes skip RESTRICTED and emit PRIVILEGE_ESCALATION instead."""
    row = _scenario_row(report, "realmcase_46")
    expected = _scenario_row(expected_report, "realmcase_46")
    assert row == expected
    assert any(f["kind"] == "PRIVILEGE_ESCALATION" for f in row["findings"])
    assert not any(f["kind"] == "RESTRICTED_ESCALATION" for f in row["findings"])


def test_realmcase_47_same_seq_sort_runs_authority_before_allow(
    report: dict[str, Any], expected_report: dict[str, Any]
) -> None:
    """Same seq: (seq, realm_id, event_id) sorts AUTHORITY before ALLOW → UNTRUSTED_REALM."""
    row = _scenario_row(report, "realmcase_47")
    expected = _scenario_row(expected_report, "realmcase_47")
    assert row == expected
    untrusted = [f for f in row["findings"] if f["kind"] == "UNTRUSTED_REALM"]
    assert len(untrusted) == 1
    assert untrusted[0]["entity_id"] == "target"
    assert untrusted[0]["detail"] == "actor"


def test_realmcase_49_quarantine_blocks_bind_not_authority(
    report: dict[str, Any], expected_report: dict[str, Any]
) -> None:
    """QUARANTINE blocks BIND but must not block AUTHORITY_ACTION (unlike SUSPEND)."""
    row = _scenario_row(report, "realmcase_49")
    expected = _scenario_row(expected_report, "realmcase_49")
    assert row == expected
    assert any(f["kind"] == "QUARANTINED_REALM" and f["detail"] == "bind" for f in row["findings"])
    assert not any(f["kind"] == "SUSPENDED_REALM" for f in row["findings"])
    assert not any(f["kind"] == "UNTRUSTED_REALM" for f in row["findings"])


def test_realmcase_50_seal_blocks_authority_allow_bind_survive_unseal(
    report: dict[str, Any], expected_report: dict[str, Any]
) -> None:
    """SEAL blocks AUTHORITY only; ALLOW/BIND still succeed; UNSEAL clears seal only."""
    row = _scenario_row(report, "realmcase_50")
    expected = _scenario_row(expected_report, "realmcase_50")
    assert row == expected
    sealed = [f for f in row["findings"] if f["kind"] == "SEALED_REALM"]
    assert len(sealed) == 1
    assert sealed[0]["detail"] == "actor"
    assert sealed[0]["event_seq"] == 6
    assert not any(f["kind"] == "QUARANTINED_REALM" for f in row["findings"])
    actor = next(r for r in row["realms"] if r["realm_id"] == "actor")
    assert "ok:scope" in actor["bound_scopes"]


def test_realmcase_51_pinned_survives_revoke_and_expiry(
    report: dict[str, Any], expected_report: dict[str, Any]
) -> None:
    """Pinned scope survives via_edge revoke + expires_at_seq; unpinned temp causes PRIVILEGE."""
    row = _scenario_row(report, "realmcase_51")
    expected = _scenario_row(expected_report, "realmcase_51")
    assert row == expected
    leaf = next(r for r in row["realms"] if r["realm_id"] == "leaf")
    assert leaf["bound_scopes"] == ["pin:read"]
    esc = [f for f in row["findings"] if f["kind"] == "PRIVILEGE_ESCALATION"]
    assert len(esc) == 1
    assert esc[0]["detail"] == "temp:read"


def test_realmcase_52_attenuate_strips_unpinned_pin_survives(
    report: dict[str, Any], expected_report: dict[str, Any]
) -> None:
    """attenuate_on_allow strips unpinned child scopes; pinned scopes survive."""
    row = _scenario_row(report, "realmcase_52")
    expected = _scenario_row(expected_report, "realmcase_52")
    assert row == expected
    child = next(r for r in row["realms"] if r["realm_id"] == "child")
    assert child["bound_scopes"] == ["pin:c", "shared:a"]
    esc = next(f for f in row["findings"] if f["kind"] == "PRIVILEGE_ESCALATION")
    assert esc["detail"] == "extra:b"


def test_realmcase_53_rotate_trust_domain_resets_registered_and_effective(
    report: dict[str, Any], expected_report: dict[str, Any]
) -> None:
    """ROTATE_TRUST_DOMAIN must overwrite registered and effective together → DOMAIN_CONTAMINATION."""
    row = _scenario_row(report, "realmcase_53")
    expected = _scenario_row(expected_report, "realmcase_53")
    assert row == expected
    contam = next(f for f in row["findings"] if f["kind"] == "DOMAIN_CONTAMINATION")
    assert contam["entity_id"] == "leaf"
    assert contam["detail"] == "core"


def test_realmcase_54_open_authority_lex_first_partner_detail(
    report: dict[str, Any], expected_report: dict[str, Any]
) -> None:
    """open_authority_lex_first must emit OPEN_AUTHORITY_PATH detail as lex-first partner."""
    row = _scenario_row(report, "realmcase_54")
    expected = _scenario_row(expected_report, "realmcase_54")
    assert row == expected
    open_path = next(f for f in row["findings"] if f["kind"] == "OPEN_AUTHORITY_PATH")
    assert open_path["detail"] == "p_aaa"
    assert not any(f["kind"] == "ADMIN_UNBOUND" for f in row["findings"])


def test_realmcase_55_empty_event_id_whitespace_dedup_string_override_inert(
    report: dict[str, Any], expected_report: dict[str, Any]
) -> None:
    """Empty event_id never dedups; whitespace does; string \"false\" override stays inert."""
    row = _scenario_row(report, "realmcase_55")
    expected = _scenario_row(expected_report, "realmcase_55")
    assert row == expected
    assert row["duplicate_events_skipped"] == 1
    assert any(f["kind"] == "UNVERIFIED_ACTOR" for f in row["findings"])
    assert any(f["kind"] == "FEDERATION_ASYMMETRY" for f in row["findings"])
    assert not any(f["kind"] == "UNTRUSTED_REALM" for f in row["findings"])


def test_realmcase_56_suppress_lateral_and_quarantined_grantor_bind(
    report: dict[str, Any], expected_report: dict[str, Any]
) -> None:
    """suppress_lateral_movement skips LATERAL; quarantined via_edge grantor → UNAUTHORIZED_SCOPE_BIND."""
    row = _scenario_row(report, "realmcase_56")
    expected = _scenario_row(expected_report, "realmcase_56")
    assert row == expected
    assert any(f["kind"] == "UNAUTHORIZED_SCOPE_BIND" and f["detail"] == "grantor" for f in row["findings"])
    assert any(f["kind"] == "PRIVILEGE_ESCALATION" for f in row["findings"])
    assert not any(f["kind"] == "LATERAL_MOVEMENT" for f in row["findings"])


def test_realmcase_57_freeze_blocks_bind_and_authority_not_allow(
    report: dict[str, Any], expected_report: dict[str, Any]
) -> None:
    """FREEZE blocks BIND and AUTHORITY but must still allow ALLOW_FEDERATION (unlike quarantine)."""
    row = _scenario_row(report, "realmcase_57")
    expected = _scenario_row(expected_report, "realmcase_57")
    assert row == expected
    assert any(f["kind"] == "FROZEN_REALM" and f["detail"] == "bind" for f in row["findings"])
    assert any(f["kind"] == "FROZEN_REALM" and f["detail"] == "actor" for f in row["findings"])
    assert not any(f["kind"] == "QUARANTINED_REALM" for f in row["findings"])
    assert {"from_realm": "alpha", "to_realm": "beta"} in row["federation_edges"]


def test_realmcase_58_freeze_quarantine_seal_three_way_axes(
    report: dict[str, Any], expected_report: dict[str, Any]
) -> None:
    """Quarantine blocks ALLOW; freeze blocks AUTHORITY after ALLOW; seal blocks AUTHORITY after ALLOW."""
    row = _scenario_row(report, "realmcase_58")
    expected = _scenario_row(expected_report, "realmcase_58")
    assert row == expected
    kinds = {(f["kind"], f["detail"]) for f in row["findings"]}
    assert ("QUARANTINED_REALM", "from") in kinds
    assert ("FROZEN_REALM", "actor") in kinds
    assert ("SEALED_REALM", "actor") in kinds
    edges = {(e["from_realm"], e["to_realm"]) for e in row["federation_edges"]}
    assert ("frozen", "leaf") in edges
    assert ("sealed", "leaf") in edges
    assert ("q_from", "leaf") not in edges


def test_realmcase_59_active_after_seq_strictly_greater(
    report: dict[str, Any], expected_report: dict[str, Any]
) -> None:
    """At seq == active_after_seq the scope is still inactive; seq > active_after activates it."""
    row = _scenario_row(report, "realmcase_59")
    expected = _scenario_row(expected_report, "realmcase_59")
    assert row == expected
    esc = [f for f in row["findings"] if f["kind"] == "PRIVILEGE_ESCALATION"]
    assert len(esc) == 1
    assert esc[0]["detail"] == "late:read"
    assert esc[0]["event_seq"] == 6
    actor = next(r for r in row["realms"] if r["realm_id"] == "actor")
    assert set(actor["bound_scopes"]) == {"late:read", "ready:read"}


def test_realmcase_60_audit_partner_privileged_asymmetry(
    report: dict[str, Any], expected_report: dict[str, Any]
) -> None:
    """audit_partner_privileged_asymmetry must emit FEDERATION_ASYMMETRY on partner→privileged."""
    row = _scenario_row(report, "realmcase_60")
    expected = _scenario_row(expected_report, "realmcase_60")
    assert row == expected
    asym = [f for f in row["findings"] if f["kind"] == "FEDERATION_ASYMMETRY"]
    assert len(asym) == 1
    assert asym[0]["entity_id"] == "partner"
    assert asym[0]["detail"] == "vault"
    assert not any(f["kind"] == "OPEN_AUTHORITY_PATH" for f in row["findings"])


def test_realmcase_61_scope_whitespace_significant(
    report: dict[str, Any], expected_report: dict[str, Any]
) -> None:
    """Trailing-space scope names must not match trimmed propagated_scopes."""
    row = _scenario_row(report, "realmcase_61")
    expected = _scenario_row(expected_report, "realmcase_61")
    assert row == expected
    esc = next(f for f in row["findings"] if f["kind"] == "PRIVILEGE_ESCALATION")
    assert esc["detail"] == "scope:a"
    actor = next(r for r in row["realms"] if r["realm_id"] == "actor")
    assert actor["bound_scopes"] == ["scope:a "]


def test_realmcase_62_frozen_grantor_and_pinned_active_after(
    report: dict[str, Any], expected_report: dict[str, Any]
) -> None:
    """Frozen via_edge grantor → UNAUTHORIZED; pinned active_after still inactive at equality seq."""
    row = _scenario_row(report, "realmcase_62")
    expected = _scenario_row(expected_report, "realmcase_62")
    assert row == expected
    assert any(f["kind"] == "UNAUTHORIZED_SCOPE_BIND" and f["detail"] == "grantor" for f in row["findings"])
    esc = next(f for f in row["findings"] if f["kind"] == "PRIVILEGE_ESCALATION")
    assert esc["detail"] == "pin:late"
    assert esc["event_seq"] == 9
    leaf = next(r for r in row["realms"] if r["realm_id"] == "leaf")
    assert leaf["bound_scopes"] == ["pin:late"]


def test_runtime_missing_journal_exits_nonzero_without_report() -> None:
    """Missing federation_trace.ajn must abort with non-zero exit and leave no partial trust_mesh_audit.json."""
    _require_session_ready()
    sid = "realmcase_03"
    journal = TRUSTCORPUS_DIR / sid / "federation_trace.ajn"
    backup = VERIFIER_DIR / f"{sid}_journal_missing.ajn"
    VERIFIER_DIR.mkdir(parents=True, exist_ok=True)
    shutil.move(str(journal), str(backup))
    try:
        REPORT_PATH.unlink(missing_ok=True)
        proc = subprocess.run([str(BINARY)], cwd=APP_DIR, capture_output=True, text=True)
        (VERIFIER_DIR / "missing_journal.log").write_text(proc.stdout + proc.stderr, encoding="utf-8")
        assert proc.returncode != 0, "missing federation_trace.ajn must exit non-zero"
        assert not REPORT_PATH.exists(), "must not write partial trust_mesh_audit.json"
    finally:
        shutil.move(str(backup), str(journal))
        REPORT_PATH.unlink(missing_ok=True)
        _run_make("run", "missing_journal_restore.log")


def test_byte_identical_report_sha256_and_outbox_prune_under_absolute_paths(
    report: dict[str, Any],
) -> None:
    """Repeated make run stays byte-identical; prune removes stale files and subdirectories under /app/outbox."""
    baseline = REPORT_FIRST.read_bytes()
    digest = hashlib.sha256(baseline).hexdigest()
    assert REPORT_PATH.read_bytes() == baseline
    assert str(REPORT_PATH) == "/app/outbox/trust_mesh_audit.json"

    stale_dir = OUTBOX_DIR / "stale_probe_dir"
    stale_dir.mkdir(exist_ok=True)
    (stale_dir / "nested.json").write_text('{"nested":true}\n', encoding="utf-8")
    for idx in range(22, 24):
        stale = OUTBOX_DIR / f"stale_probe_{idx}.json"
        stale.write_text('{"probe":true}\n', encoding="utf-8")
        try:
            _run_make("run", f"prune_chain_{idx}.log")
            names = {p.name for p in OUTBOX_DIR.iterdir()}
            assert names == {"realmshadow", "trust_mesh_audit.json"}
            raw = REPORT_PATH.read_bytes()
            assert raw == baseline, f"run {idx} diverged"
            assert hashlib.sha256(raw).hexdigest() == digest
        finally:
            stale.unlink(missing_ok=True)
            if stale_dir.exists():
                shutil.rmtree(stale_dir)

    assert _report_digest(report) == hashlib.sha256(
        json.dumps(report, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
