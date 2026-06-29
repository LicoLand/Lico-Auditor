# LicoLite Privacy Gate

`licolite-audit` is an external audit gate for `LicoLite/licolite`.
The audit repository is governed by a single `only` branch. All Actions must
run the latest `only` HEAD and fail if any other audit branch is reachable.

The current policy blocks public release when reachable worktree content, git
history, or GitHub surfaces expose:

- developer workstation paths or repository roots;
- any committed IP literal except local loopback;
- host/domain endpoints outside localhost, licolite.com, and licolite.app;
- production backend/admin endpoint/provider metadata;
- private key blocks, credential URLs, authorization/API-key headers, JWT-like
  tokens, cloud access tokens, and secret-like assignments;
- SSH public key material in templates;
- known previously leaked local-path markers and retired public-domain markers;
- GitHub pull request refs in a freshly republished clean repository.

Findings intentionally do not print matched values. Reports include only rule
id, file, line, column, evidence class, commit, and a short fingerprint.
Personal names and email addresses are intentionally out of scope for this first
gate; the current blocker is backend infrastructure and local filesystem
metadata.
Any `high-risk` or `error` finding is a hard failure.
