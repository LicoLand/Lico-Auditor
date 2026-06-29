# licolite-audit

External privacy and release audit gate for LicoLite.

The framework is intentionally outside the target repository. It checks the
target checkout as data, reports only redacted evidence, and fails when privacy
or local-info leakage is reachable from public branches.
It currently governs `LicoLite/licolite`, `LicoLite/licolite-skills`, and
`LicoLite/licolite.com`.

The `only` branch is the sole source of truth. CI jobs must checkout
`LicoLite/licolite-audit@only`, verify that the remote exposes no other audit
branch, and run the gate from the latest `only` HEAD before any target scan.

## Commands

```sh
bin/licolite-audit gate --repo ../licolite --profile platform --history
bin/licolite-audit report --repo ../licolite --profile platform --history --format json
bin/licolite-audit github-surface --all-targets
bin/licolite-audit source-of-truth --repo . --require-current-head --enforce-remote-heads
```

`gate` is suitable for CI. `report` emits a structured JSON payload. Neither
command prints the matched sensitive value.

## Policy Profiles

Every repository runs the `common` baseline: source-of-truth checks, data-file
default denial, user-record shape blocking, host/IP restrictions, secrets,
local paths, operational endpoints, and GitHub surface checks.

Repository-specific profiles only define what engineering files are allowed:

- `platform` for `LicoLite/licolite`: admits the platform's fixed configuration
  and registry JSON directories, and requires schema-like object shape there.
- `website` for `LicoLite/licolite.com`: admits only common website/build
  metadata such as package and TypeScript config JSON; arbitrary content/data
  JSON is denied by default.
- `skills` for `LicoLite/licolite-skills`: admits skill template JSON assets
  and common build metadata; operational or customer-like data files remain
  denied.
- `common` for organization/community support repositories: no product-specific
  config paths are inherited.

Actions that checkout a target into a generic path such as `target/` must pass
`--profile` explicitly. In a normal repository checkout, `auto` maps known repo
names to the correct profile.

## Current Gate Scope

- developer workstation and workspace paths;
- data files are denied by default: JSON outside approved configuration paths,
  JSONL/NDJSON, CSV/TSV, SQL dumps, database files, spreadsheets, parquet, and
  other export-like formats;
- fixed configuration directories must contain schema-checked JSON only;
- allowlisted JSON must look like project configuration, registry, manifest, or
  template objects, and user/customer/contact/account record-shaped JSON is
  blocked even inside allowlisted paths;
- any committed IP literal except local loopback;
- host/domain endpoints outside localhost, licolite.com, and licolite.app;
- production backend/admin endpoint/provider metadata;
- customer, tenant, contract, revenue, commercial account, and other
  business-confidential values;
- production deployment, cloud resource, backend service, cluster, region,
  bucket, database, image, registry, or namespace metadata in operational
  material;
- private keys, credential URLs, authorization headers, JWTs, cloud access
  tokens, and secret-like configuration assignments;
- committed SSH public key material;
- known previously leaked local-path and retired-domain markers;
- GitHub PR refs after clean repository publication.

Any `high-risk` or `error` finding exits non-zero. There is no warning-only mode
for release gates.

See [PRIVACY-GATE.md](docs/specs/PRIVACY-GATE.md).
