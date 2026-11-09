# Workspace layout (read-only)

Read this file and all other `/app/fedproto/*.md` specs **before** editing Go source.

## Module and imports

`/app/go.mod` declares:

```
module realmshadow
```

All import paths must use the `realmshadow/...` prefix. Examples that **work**:

- `realmshadow/pkg/wireajn`
- `realmshadow/pkg/trustmesh`
- `realmshadow/pkg/policygate`

Import paths use the `realmshadow/...` module root declared in `go.mod`.

## Editable directories (agent may modify)

| Path | Role |
|------|------|
| `/app/svc/realmshadow/main.go` | Program entry; loads `trust_index.json`, decodes journals, writes `trust_mesh_audit.json` |
| `/app/pkg/wireajn/decode.go` | AJN1 little-endian journal decoder (`AJN1_WIRE_FORMAT.md`) |
| `/app/pkg/trustmesh/replay.go` | Authority replay engine (`TRUST_MESH_REPLAY.md`) |
| `/app/pkg/policygate/policy.go` | Scenario policy override helpers |

The Makefile builds `./svc/realmshadow` only.

## Immutable inputs (do not modify)

| Path | Role |
|------|------|
| `/app/trustcorpus/` | Bundled scenarios (`realmcase_XX.json` + `realmcase_XX/federation_trace.ajn`) |
| `/app/trustcorpus/trust_index.json` | Scenario processing order |
| `/app/fedproto/` | Specifications (this directory) |
| `/app/Makefile`, `/app/go.mod` | Build wiring |

## Outputs

| Path | Role |
|------|------|
| `/app/outbox/realmshadow` | Built Go binary (`make build`) |
| `/app/outbox/trust_mesh_audit.json` | Compact JSON audit snapshot (`make run`) |

After each successful `make run`, `/app/outbox` must contain only those two entries. Before writing the new snapshot, remove every other file and subdirectory under `/app/outbox`.

## Build commands

```bash
make build   # go build -o outbox/realmshadow ./svc/realmshadow
make run     # build then execute /app/outbox/realmshadow
```

Read `AJN1_WIRE_FORMAT.md`, `TRUST_MESH_REPLAY.md`, and `AUDIT_SNAPSHOT_SCHEMA.md` next.
