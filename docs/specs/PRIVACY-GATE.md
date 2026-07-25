# Lico-Auditor Privacy Gate

`lico-auditor` is the external audit gate for governed Meshrix, LicoUp,
BadTower, and Fabrigent repositories. The audit repository is governed by a
single `only` branch. All
Actions must run the latest `only` HEAD and fail if any other audit branch is
reachable.
The current governed targets cover Meshrix core, services, and plugins;
LicoUp; BadTower; Fabrigent; the retained independent `LicoArc-Plugins`
marketplace; developer and organization governance; and official website
repositories.

## Policy Profiles

The gate is layered:

- `common` is mandatory for every public repository and contains the shared
  hard blockers: unapproved data files, user-record shaped JSON, secrets,
  endpoint/IP/domain rules, local paths, operational metadata, and GitHub
  surface checks.
- `meshrix` applies to Meshrix, Meshrix-Services, and Meshrix-Plugins. It
  admits the platform's known configuration, registry, service-contract, and
  plugin-manifest JSON paths, then validates their configuration shape.
- `licoup` applies to the client repository `LicoLand/LicoUp`. It admits
  client contracts, desktop assets, native resource manifests, and reviewed
  client tooling JSON; arbitrary export-like data files remain denied.
- `badtower` applies to `LicoLand/BadTower`. It admits node-owned
  configuration, implementation schemas, registries, and synthetic examples;
  protocol and federation policy authority remain outside this profile.
- `fabrigent` applies to `LicoLand/Fabrigent`. It admits public protocol
  schemas, policy definitions, registries, and generated projections.
- `website` applies to official public website repositories. It does not inherit Meshrix
  configuration paths; arbitrary JSON content/data files are denied unless a
  future website-specific schema is added here.
- `skills` applies to `LicoLand/Lico-Dev`. It admits canonical
  `config/<canonical-name>.json` repository-policy objects under a strict
  field-and-type schema, canonical skill/workflow manifests, template JSON at
  `skills/*/assets/*.template.json`, and common build metadata. Unknown
  configuration fields fail closed; operational exports, databases, and
  customer-shaped data remain denied.

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
- host/domain endpoints outside localhost and the official `lico.land`,
  `licoland.com`, `meshrix.io`, `licomesh.com`, `licoup.com`, `licoup.net`,
  and `licoarc.com` namespaces;
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
- Cursor attribution in contributor files, project author metadata, commit
  author or committer identity, and attribution trailers such as `Made-with`
  or `Co-authored-by`;
- local branch names beginning with `codex`, which must be replaced with a
  meaningful prefix such as `feature` or `fix`; the GitHub ruleset applies the
  same restriction before remote branch creation or update.

Any `high-risk` or `error` finding fails the gate. There is no warning-only
mode for release gates.

## GitHub Enforcement

`.github/rulesets/contribution-governance.json` is the canonical importable
organization ruleset. It rejects `codex`-prefixed branch creation or updates
and Cursor attribution in commit messages, author email, or committer email
before GitHub accepts the ref update. It targets every governed public
repository and has no bypass actors.

GitHub metadata rules cannot inspect contributor files or author display
names. Governed repositories must therefore call
`.github/workflows/contribution-governance.yml` and require its
`contribution-governance` job in the branch ruleset. The reusable workflow
checks the pull request or push commit range and current candidate tree with
the canonical `only` version of Lico-Auditor. The independent scheduled audit
continues to inspect complete reachable history without a legacy baseline.

## Documentation Governance

The `meshrix`, `licoup`, `badtower`, and `fabrigent` profiles also validate
the current tracked documentation publication candidate. The check covers the required public
layout, bilingual README mapping, formal-document categories and index,
relative links, module READMEs, generated-projection metadata, local-only
ignore boundaries, and external skill ownership.

This structural gate does not claim that document content is semantically
correct. Capability truth, canonical fact ownership, ADR evidence, and release
provenance remain the responsibility of the target repository's code, schemas,
registries, and verifiers.

See
[Meshrix, LicoUp, BadTower, and Fabrigent Documentation Governance Gate](DOCUMENTATION-GOVERNANCE.md).
