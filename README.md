# Lico-Auditor

External privacy and release audit gate for governed Meshrix, LicoUp,
BadTower, and Fabrigent repositories.

The framework is intentionally outside the target repository. It checks the
target checkout as data, reports only redacted evidence, and fails when privacy
or local-info leakage is reachable from public branches.
It governs the Meshrix core, services, and plugins repositories; LicoUp;
BadTower; Fabrigent; the retained independent `LicoArc-Plugins` marketplace;
organization governance; developer intent; and the official public website
repositories.

The `only` branch is the sole source of truth. CI jobs must checkout
`LicoLand/Lico-Auditor@only`, verify that the remote exposes no other audit
branch, and run the gate from the latest `only` HEAD before any target scan.

## Commands

```sh
bin/lico-auditor gate --repo ../Meshrix --profile meshrix --history
bin/lico-auditor gate --repo ../LicoUp --profile licoup --history
bin/lico-auditor gate --repo ../BadTower --profile badtower --history
bin/lico-auditor gate --repo ../Fabrigent --profile fabrigent --history
bin/lico-auditor report --repo ../Meshrix --profile meshrix --history --format json
bin/lico-auditor github-surface --all-targets
bin/lico-auditor source-of-truth --repo . --require-current-head --enforce-remote-heads
```

`gate` is suitable for CI. `report` emits a structured JSON payload. Neither
command prints the matched sensitive value.

## Policy Profiles

Every repository runs the `common` baseline: source-of-truth checks, data-file
default denial, user-record shape blocking, host/IP restrictions, secrets,
local paths, operational endpoints, and GitHub surface checks.

Repository-specific profiles only define what engineering files are allowed:

- `meshrix` for Meshrix, Meshrix-Services, and Meshrix-Plugins: admits fixed
  platform configuration, registries, service contracts, and plugin manifests.
- `licoup` for `LicoLand/LicoUp`: admits client contracts, desktop assets,
  native resource manifests, and reviewed client tooling JSON.
- `badtower` for `LicoLand/BadTower`: admits only node-owned configuration,
  implementation schemas, registries, and synthetic documentation examples.
  It does not establish protocol or federation policy authority.
- `fabrigent` for `LicoLand/Fabrigent`: admits public federation protocols,
  policy definitions, schemas, registries, and generated projections.
- `website` for `LicoLand/licomesh.com`: admits only common website/build
  metadata such as package and TypeScript config JSON; arbitrary content/data
  JSON is denied by default.
- `skills` for `LicoLand/Lico-Dev`: admits template JSON only at
  `skills/*/assets/*.template.json` plus common build metadata; operational or
  customer-like data files remain denied.
- `common` for organization and retained support repositories: no product-specific
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
- host/domain endpoints outside localhost and the official `lico.land`,
  `licoland.com`, `meshrix.io`, `licomesh.com`, `licoup.com`, `licoup.net`,
  and `licoarc.com` namespaces;
- production backend/admin endpoint/provider metadata;
- customer, tenant, contract, revenue, commercial account, and other
  business-confidential values;
- production deployment, cloud resource, backend service, cluster, region,
  bucket, database, image, registry, or namespace metadata in operational
  material;
- private keys, credential URLs, authorization headers, JWTs, cloud access
  tokens, and secret-like configuration assignments;
- committed SSH public key material;
- GitHub PR refs after clean repository publication.
- Cursor attribution in contributor lists, project author metadata, Git author
  or committer identity, and commit attribution trailers including
  `Made-with` and `Co-authored-by`;
- local branches whose names use the `codex` prefix instead of a meaningful
  prefix such as `feature` or `fix`, with the same restriction enforced on
  GitHub branches by the importable ruleset;
- tracked documentation governance for the `meshrix`, `licoup`, `badtower`,
  and `fabrigent` profiles:
  required public entry points, approved formal-document categories, bilingual
  README mapping, index and link integrity, module READMEs, generated-source
  metadata, and local-only asset boundaries;

Any `high-risk` or `error` finding exits non-zero. There is no warning-only mode
for release gates.

See [PRIVACY-GATE.md](docs/specs/PRIVACY-GATE.md).
See
[DOCUMENTATION-GOVERNANCE.md](docs/specs/DOCUMENTATION-GOVERNANCE.md)
for the four current product profiles' documentation audit contract.
