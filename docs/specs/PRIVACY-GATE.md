# LicoLite Privacy Gate

`licolite-audit` is an external audit gate for `LicoLite/licolite`.
The audit repository is governed by a single `only` branch. All Actions must
run the latest `only` HEAD and fail if any other audit branch is reachable.
The current governed targets are `LicoLite/licolite`, `LicoLite/licolite-skills`,
and `LicoLite/licolite.com`.

## Policy Profiles

The gate is layered:

- `common` is mandatory for every public repository and contains the shared
  hard blockers: unapproved data files, user-record shaped JSON, secrets,
  endpoint/IP/domain rules, local paths, operational metadata, and GitHub
  surface checks.
- `platform` applies to the real platform code repository `LicoLite/licolite`.
  It admits only the platform's known configuration and registry JSON paths,
  then validates that those files remain schema/config shaped.
- `website` applies to `LicoLite/licolite.com`. It does not inherit platform
  configuration paths; arbitrary JSON content/data files are denied unless a
  future website-specific schema is added here.
- `skills` applies to `LicoLite/licolite-skills`. It admits skill template JSON
  assets and common build metadata, but not operational exports, databases, or
  customer-shaped data.

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
  record-shaped structure;
- any committed IP literal except local loopback;
- host/domain endpoints outside localhost, licolite.com, and licolite.app;
- production backend/admin endpoint/provider metadata;
- customer, tenant, contract, revenue, commercial account, and other
  business-confidential values;
- production deployment, cloud resource, backend service, cluster, region,
  bucket, database, image, registry, or namespace metadata in operational
  material;
- private key blocks, credential URLs, authorization/API-key headers, JWT-like
  tokens, cloud access tokens, and secret-like assignments;
- SSH public key material in templates;
- known previously leaked local-path markers and retired public-domain markers;
- GitHub pull request refs in a freshly republished clean repository.

Findings intentionally do not print matched values. Reports include only rule
id, file, line, column, evidence class, commit, and a short fingerprint.
Personal names and email addresses are intentionally out of scope because the
project owner has approved those identities for public Git history. Backend
infrastructure, local filesystem metadata, and business-confidential deployment
or commercial information are hard blockers.

The primary control is not a sensitive-word list. The release gate is
deny-by-default for data-shaped files, then admits only known project
configuration paths and validates their file type and JSON object shape.
Keyword and endpoint rules remain as defense-in-depth for plain text leakage.
Any `high-risk` or `error` finding is a hard failure.
