# trust_mesh_audit.json schema (read-only specification)

Output shape for `/app/outbox/trust_mesh_audit.json`. Do not edit files under `/app/fedproto/`.

Fixtures live under `/app/trustcorpus` as `realmcase_XX.json` (01–62) plus `/app/trustcorpus/realmcase_XX/federation_trace.ajn` (AJN1 little-endian per `AJN1_WIRE_FORMAT.md`). JSON files hold scenario defaults only (no `events` array). `/app/trustcorpus/trust_index.json` lists `scenarios` in processing order.

Root: `{ "scenarios": [ ... ] }` in manifest order.

Each scenario:

```json
{
  "scenario_id": "realmcase_01",
  "status": "VALID",
  "duplicate_events_skipped": 0,
  "journal": {
    "format_version": 1,
    "records_total": 5,
    "records_valid": 5,
    "records_rejected": 0,
    "dup_seq_rejects": 0,
    "truncated_tail": 0,
    "payload_bytes": 512
  },
  "federation_edges": [
    {"from_realm": "orders", "to_realm": "billing"}
  ],
  "realms": [
    {
      "realm_id": "billing",
      "tier": "internal",
      "bound_scopes": ["billing:read"],
      "authority_risk": "none"
    }
  ],
  "findings": []
}
```

## journal object

Only these keys, in this order:

`format_version`, `records_total`, `records_valid`, `records_rejected`, `dup_seq_rejects`, `truncated_tail`, `payload_bytes`

Values come from AJN1 decode per `AJN1_WIRE_FORMAT.md`. `records_total` counts only records whose complete 12-byte header was read. `truncated_tail` is a 0/1 flag.

`federation_edges` sorted by `(from_realm, to_realm)` ascending.

`realms` sorted by `realm_id`. Each realm contains only: `realm_id`, `tier`, `bound_scopes` (sorted array), `authority_risk`.

### authority_risk (realm rows only)

Use **only** these lowercase strings: `none`, `elevated`, `critical`. No other spellings or synonyms (for example not `low`, `medium`, `high`, `LOW`, `MEDIUM`, `HIGH`). Map from `tier`:

| `tier` | `authority_risk` |
|--------|------------------|
| `internal` | `none` |
| `partner` | `elevated` |
| `privileged` | `critical` |

Each finding:

```json
{
  "finding_id": "realmcase_03::billing::0004",
  "entity_id": "billing",
  "kind": "UNTRUSTED_REALM",
  "event_seq": 4,
  "action": "<event.action>",
  "detail": "orders"
}
```

`kind` is exactly one of the kinds listed in TRUST_MESH_REPLAY.md. Multiple findings may share the same `finding_id`; emit one row per finding and do not collapse duplicates. `findings` sorted by `(finding_id, kind)` ascending lexicographically. Use `[]` never null.

For findings emitted while processing an `AUTHORITY_ACTION` journal event, `action` must equal that event's `action` field. All other findings (including audit post-check rows) use `action` = `""`.

## JSON arrays (never null)

Every list field in the snapshot must serialize as a JSON array, including when empty. Use `[]`, never `null`, for: root `scenarios`, each scenario's `federation_edges`, `realms`, `bound_scopes`, and `findings`. Emit zero-length slices in Go (for example `[]Finding{}`), not nil slices that marshal to `null`.

Encoding: compact JSON with `separators=(",", ":")` — no space after `:` or `,`. UTF-8, LF line endings, exactly one trailing newline.

## Build output layout

After `make run`, `/app/outbox` must contain exactly two entries: the `realmshadow` binary and `trust_mesh_audit.json`. No other files or subdirectories may remain in that directory.
