# LicoLite Privacy Gate

`licolite-audit` is an external audit gate for `LicoLite/licolite`.
The audit repository is governed by a single `only` branch. All Actions must
run the latest `only` HEAD and fail if any other audit branch is reachable.
The current governed targets are `LicoLite/licolite`, `LicoLite/licolite-skills`,
and `LicoLite/licolite.com`.

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
