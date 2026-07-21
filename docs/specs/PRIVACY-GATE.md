# Lico-Auditor Privacy Gate

`lico-auditor` is the external audit gate for governed LicoMesh and LicoArc
repositories. The audit repository is governed by a single `only` branch. All
Actions must run the latest `only` HEAD and fail if any other audit branch is
reachable.
The current governed targets are `LicoLand/LicoMesh`, `LicoLand/LicoArc`,
`LicoLand/Lico-Dev`, `LicoLand/licomesh.com`, `LicoLand/.github`, and
`LicoLand/licomesh-community`.

## Policy Profiles

The gate is layered:

- `common` is mandatory for every public repository and contains the shared
  hard blockers: unapproved data files, user-record shaped JSON, secrets,
  endpoint/IP/domain rules, local paths, operational metadata, and GitHub
  surface checks.
- `platform` applies to the real platform code repository `LicoLand/LicoMesh`.
  It admits only the platform's known configuration and registry JSON paths,
  then validates that those files remain schema/config shaped.
- `client` applies to the client repository `LicoLand/LicoArc`. It admits
  client contracts, desktop assets, native resource manifests, and reviewed
  client tooling JSON; arbitrary export-like data files remain denied.
- `website` applies to `LicoLand/licomesh.com`. It does not inherit platform
  configuration paths; arbitrary JSON content/data files are denied unless a
  future website-specific schema is added here.
- `skills` applies to `LicoLand/Lico-Dev`. It admits template JSON only at
  `skills/*/assets/*.template.json` plus common build metadata, but not
  operational exports, databases, or customer-shaped data.

The centralized Action checks targets out under `target/`, so it must pass the
profile explicitly. Repository-local workflows may use `auto`, which maps known
repository names to the matching profile.

The current policy blocks public release when reachable worktree content, git
history, or GitHub surfaces expose:

- developer workstation paths or repository roots;
- data files by default, including JSON outside approved configuration paths,
  JSONL/NDJSON, CSV/TSV, SQL dumps, database files, spreadsheets, parquet, and
  other export-like formats;
- files in fixed configuration directories unless they are schema-checked JSON;
- allowlisted JSON that has user, customer, contact, account, or people
  record-shaped payloads;
- any non-loopback IP literal;
- host/domain endpoints outside localhost, licomesh.com, and licomesh.app;
- production backend/admin endpoint or provider metadata;
- customer, tenant, contract, revenue, commercial account, and other
  business-confidential values;
- production deployment, cloud resource, backend service, cluster, region,
  bucket, database, image, registry, or namespace metadata in operational
  material;
- private keys, credential URLs, authorization headers, JWTs, cloud access
  tokens, and secret-like configuration assignments;
- committed SSH public key material;
- GitHub pull refs after clean repository publication.

Any `high-risk` or `error` finding fails the gate. There is no warning-only
mode for release gates.
