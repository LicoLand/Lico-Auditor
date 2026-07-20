# Lico-Auditor Agent Instructions

<!-- licomesh-dev:shared-rules:start -->
## Shared rules

- **parallel-work** — Delegate independent, bounded work to subagents when parallel execution materially improves speed or quality. Prefer fast models for simple text or code work and deep models for complex work; record any fallback when the requested class is unavailable.
- **privacy** — Never disclose machine identity, non-public personal data, secrets, ciphertext, protected backend data, raw runtime data, or sensitive command output. Deliberately published developer identity such as a project contact email or GitHub username may remain public; it never authorizes exposing a local account, host, path, device, credential, or unrelated metadata. Emit only redacted, minimum-necessary evidence.
- **public-release-boundary** — Keep development, ordinary verification, packaging, GitHub Release, and every platform store or channel as separate claims. Missing publisher accounts, store credentials, signing or notarization identities, listings, or channel access are non-blocking guidance outside an explicitly requested release to that specific store or channel. Public release metadata is limited to artifact name, version, platform, byte size, cryptographic digest, detached signature, verification algorithm or key identifier, only the public verification key or certificate-chain fields required to validate that signature, and cryptographically bound provenance or attestation when it is itself part of verification. Omit publisher, account, team, tenant, device, profile, credential, private-channel, and internal release metadata.
- **complete-migration** — Complete refactors and migrations in one pass. Remove superseded implementations, names, paths, compatibility layers, tests, and documentation unless the user explicitly requires coexistence.
- **retired-state-reset** — Persistent user state owned by a retired product name is reset, not migrated. The current product must initialize fresh current-name state and must never discover, import, rename, copy, translate, or prompt for a retired-name data root or preference namespace; do not preserve legacy-state fixtures or compatibility gates.
- **algorithm-quality** — For algorithmic or data-structure work, compare relevant primary or open-source implementations, choose appropriate structures and caching, avoid repeated computation, and optimize scheduling, memory, and concurrency.
- **retired-artifacts** — Removed code and documentation must not remain as permanent tests, fixtures, compatibility checks, or release gates.
<!-- licomesh-dev:shared-rules:end -->

<!-- licomesh-dev:repository-scope:start -->
## Repository scope

- Own independent audit policy, audit profiles, and audit evidence contracts for governed LicoMesh and LicoArc repositories.
- Keep product implementation and runtime data outside this repository.
- Do not emit matched secret or private data in audit output.
<!-- licomesh-dev:repository-scope:end -->

## 品牌形象与组织基因

- LicoMesh 的四个核心词是：**多元、互联、开放、融合**。
- 本仓库是跨产品外部审计门禁。这里体现四个词的方式不是营销文案，而是让 LicoMesh 与 LicoArc 的多仓库、多服务、多发布面能够开放协作，同时通过隐私门禁、事实源检查、脱敏证据和 profile 化策略保持可治理、可发布、可恢复。
- 维护 `README.md`、`docs/specs/PRIVACY-GATE.md`、policy profiles 或 audit rules 时，保持这种产品气质：开放发布但不泄露本地或生产细节；多项目互联但每个边界有清晰 profile；证据融合到可审计报告中。
