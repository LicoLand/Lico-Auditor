# Lico-Auditor

External privacy and release audit gate for governed LicoUp, BadTower, and
Fabrigent repositories.

The framework is intentionally outside the target repository. It checks the
target checkout as data, reports only redacted evidence, and fails when privacy
or local-info leakage is reachable from public branches.
It governs LicoUp; BadTower; Fabrigent; the retained independent
`LicoArc-Plugins` marketplace;
organization governance; developer intent; and the official public website
repositories.

The `only` branch is the sole source of truth. CI jobs must checkout
`LicoLand/Lico-Auditor@only` and run the gate from the latest `only` HEAD before
any target scan. Temporary branches support normal pull-request maintenance and
do not affect consumers.

## Commands

```sh
bin/lico-auditor gate --repo ../LicoUp --profile licoup --history
bin/lico-auditor gate --repo ../BadTower --profile badtower --history
bin/lico-auditor gate --repo ../Fabrigent --profile fabrigent --history
bin/lico-auditor report --repo ../LicoUp --profile licoup --history --format json
bin/lico-auditor github-surface --all-targets
bin/lico-auditor source-of-truth --repo . --require-current-head
```

`gate` is suitable for CI. `report` emits a structured JSON payload. Neither
command prints the matched sensitive value.

## Independent release gate

First-party repositories call
`.github/workflows/release-audit.yml@only` from the organization repository
template. The caller uses `pull_request_target`, default-branch pushes, stable
release tags, and explicit dispatches; the reusable workflow accepts no
repository, ref, or profile override from the caller.

The gate runs only canonical Lico-Auditor code and treats the candidate checkout
as data:

1. verify that the audit code matches the latest `only` branch;
2. resolve the policy profile from the owning repository name;
3. audit the candidate commit range, including contribution metadata; and
4. on a stable tag or explicit readiness dispatch, audit all reachable content
   history with contribution-history noise disabled.

The fourth step still scans every historical file for privacy, secret, local
machine, user-record, and governed data-policy findings. It suppresses only
historical attribution that is separately enforced on the candidate range.
The workflow has read-only contents permission, receives no secrets, persists
no checkout credential, and never executes target-repository code.

This audit is independent of the organization version-contract verifier and
of repository-owned build or acceptance checks. A tag is not eligible for a
GitHub Release until all three claims succeed. There is no warning-only or
administrator-bypass release mode.

## Policy Profiles

Every repository runs the `common` baseline: source-of-truth checks, data-file
default denial, user-record shape blocking, host/IP restrictions, secrets,
local paths, operational endpoints, and GitHub surface checks.

Repository-specific profiles only define what engineering files are allowed:

- `licoup` for `LicoLand/LicoUp`: admits client contracts, desktop assets,
  update public-key metadata, native resource and model-reference catalogs,
  reviewed client tooling JSON, and official public vendor references.
- `badtower` for `LicoLand/BadTower`: admits only node-owned configuration,
  implementation schemas, registries, and synthetic documentation examples.
  It does not establish protocol or federation policy authority.
- `fabrigent` for `LicoLand/Fabrigent`: admits public federation protocols,
  policy definitions, schemas, registries, and generated projections.
- `website` for `LicoLand/licomesh.com`: admits only common website/build
  metadata such as package and TypeScript config JSON; arbitrary content/data
  JSON is denied by default.
- `skills` for `LicoLand/Lico-Dev`: admits strictly shaped canonical
  repository-policy JSON under `config/`, canonical skill/workflow manifests,
  template JSON at `skills/*/assets/*.template.json`, and common build
  metadata. Unknown fields, operational data, and customer-like data remain
  denied.
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
  template objects; GitHub workflow-template metadata is limited to the exact
  `workflow-templates/*.properties.json` schema; and
  user/customer/contact/account record-shaped JSON is blocked even inside
  allowlisted paths;
- any committed IP literal except local loopback;
- host/domain endpoints outside localhost and the official `lico.land`,
  `licoland.com`, `licomesh.com`, `licoup.com`, `licoup.net`,
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
- tracked documentation governance for the `licoup`, `badtower`, and
  `fabrigent` profiles:
  required public entry points, approved formal-document categories, bilingual
  README mapping, index and link integrity, module READMEs, generated-source
  metadata, and local-only asset boundaries;

Any `high-risk` or `error` finding exits non-zero. There is no warning-only mode
for release gates.

See [PRIVACY-GATE.md](docs/specs/PRIVACY-GATE.md).
See
[DOCUMENTATION-GOVERNANCE.md](docs/specs/DOCUMENTATION-GOVERNANCE.md)
for the three current product profiles' documentation audit contract.

## Version governance

The structured repository version authority is
[`docs/releases/plan.json`](docs/releases/plan.json). Its generated
human-readable projection is
[`docs/releases/README.md`](docs/releases/README.md).
