# AJN1 replication journal format (read-only)

Authority replay events ship as little-endian binary under `/app/trustcorpus/{scenario_id}/federation_trace.ajn`. Scenario defaults live in `/app/trustcorpus/{scenario_id}.json` (no `events` array).

## File header

| Offset | Field | Type | Rule |
|--------|-------|------|------|
| 0 | magic | 4 bytes | `AJN1` |
| 4 | `format_version` | uint32 **LE** | must be `1`; otherwise fatal (exit non-zero, no report) |

The on-wire record header is exactly **12 bytes** before `payload`: `uint32 record_seq` + `uint16 flags` + `uint16 reserved` + `uint32 payload_len`, all little-endian. Each field is decoded independently; `format_version` in the file header is also little-endian.

If a scenario `federation_trace.ajn` is missing, unreadable, or not a regular file, the program must exit non-zero and must not write `/app/outbox/trust_mesh_audit.json`.

## Records (until EOF)

| Field | Type | Rule |
|-------|------|------|
| `record_seq` | uint32 LE | wire record identity for dedup (independent of JSON `seq`) |
| `flags` | uint16 LE | must be `0` for authority payloads |
| `reserved` | uint16 LE | must be `0` |
| `payload_len` | uint32 LE | byte length of JSON payload |
| `payload` | bytes | UTF-8 JSON object for one replay event |
| `checksum` | uint32 LE | CRC-32 (IEEE) over the 12-byte header (`record_seq`, `flags`, `reserved`, `payload_len`, each little-endian) concatenated with `payload` |

Process records in file order. Each record is **valid** or **rejected**:

| Reason | Rule |
|--------|------|
| `BAD_RESERVED` | `reserved != 0` |
| `BAD_FLAGS` | `flags != 0` |
| `LEN_OVERFLOW` | `payload_len > 4096`; if the full frame fits, skip `payload` and `checksum` and continue; if bytes are missing, set `truncated_tail` and stop |
| `DUP_SEQ` | `record_seq` already seen (valid or rejected earlier) |
| `BAD_CRC` | checksum mismatch |
| `TRUNCATED` (header) | fewer than 12 bytes remain for a header |
| `TRUNCATED` (body) | fewer than `payload_len + 4` bytes remain after a full header was read |

On header `TRUNCATED`: increment `records_rejected`, set `truncated_tail` to `1`, and stop. **Do not** increment `records_total`.

On body `TRUNCATED` after a full header: increment `records_total` and `records_rejected`, set `truncated_tail` to `1`, and stop.

**`truncated_tail` is a boolean flag encoded as an integer:** it must be exactly `0` when decoding ends on a clean record boundary, or `1` when decoding stops because a record was truncated. Set it at most once, then stop decoding.

`records_total` counts only records whose complete 12-byte header was read.

Track every `record_seq` in a set, including rejected records. Increment `dup_seq_rejects` **only** when the rejection reason is `DUP_SEQ` (not for `LEN_OVERFLOW`, truncation, `BAD_CRC`, `BAD_FLAGS`, `BAD_RESERVED`, or other reasons). `payload_bytes` sums `payload_len` for **valid** records only.

Evaluate `LEN_OVERFLOW` before `DUP_SEQ` when both would apply.

Only valid payloads are unmarshalled and passed to authority replay (then `TRUST_MESH_REPLAY.md` event sort and `event_id` dedup apply). Invalid UTF-8 or non-JSON payloads after a valid CRC are **rejected** (`records_rejected++`); they do not increment `payload_bytes` or `records_valid`.

## Per-scenario journal block in the snapshot

Each scenario row includes a `journal` object (see `AUDIT_SNAPSHOT_SCHEMA.md`) with: `format_version`, `records_total`, `records_valid`, `records_rejected`, `dup_seq_rejects`, `truncated_tail`, `payload_bytes`.

All bundled journal paths are absolute under `/app/trustcorpus/{scenario_id}/federation_trace.ajn`.

## Go path wiring (required)

When opening journals from Go code, the resolved path must be `/app/trustcorpus/{scenario_id}/federation_trace.ajn`. Use a data-root token exactly `"/app/trustcorpus"` or `"/app/trustcorpus/"` visible in editable Go source (string concatenation with `+` is fine). Do not use `filepath.Join`, relative paths, or compose `/app/trustcorpus` paths without one of those root literals present in source.

Also require these visible in editable Go under `/app/svc` and `/app/pkg`:

- `federation_trace.ajn` when building journal paths
- `trust_index.json` when loading the scenario list
- the **complete** report path literal exactly `"/app/outbox/trust_mesh_audit.json"` — composing only `"/app/outbox"` plus a filename variable is not sufficient

`filepath.Join` is allowed for other paths (for example pruning filenames under `/app/outbox`). It is **not** allowed when constructing `/app/trustcorpus`, `federation_trace.ajn`, `trust_index.json`, or report paths.

Editable Go source must not embed shell command substitution (`$(...)`), backtick substitution, or semicolon-chained shell commands when building paths.
