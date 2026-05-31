# IgniteSol Security & Compliance Infrastructure — Implementation Plan (v2)

> **Status:** Locked design, pre-build. Source of truth for Phase 0+ scaffolding.
> **Owner:** Chief Security & Compliance Engineering.
> **Repo:** `ignitesol.security-infra` — central home for reusable GitHub Actions
> workflows, orchestration code, email templates, and pinned threat-intel config.
> **Last updated:** 2026-05-30.

## 1. Mandate

Provide three systems that any engineering team can **import into their GitHub
Actions workflow** in a few lines and run **regularly**:

1. **Security scan** — run a script against the codebase to check for security issues.
2. **Bumblebee** — run [perplexityai/bumblebee](https://github.com/perplexityai/bumblebee)
   to check for data leaks / supply-chain exposure.
3. **License / dependency tracker** — list dependencies added since the last run and
   categorize them by license.

All three **email a summary** at the end.

## 2. Decisions captured

| Area | Decision |
|---|---|
| CI platform | **GitHub Actions** — shipped as reusable workflows (`workflow_call`) adopting repos call in a few lines |
| Triggers / cadence | **Fully team-owned.** Reusable workflows declare no `on:`/cron. Teams set schedule (cron), push filters, and `workflow_dispatch` in their own caller workflow. Suggested crons shipped in `examples/` as guidance only |
| Email transport | **AWS SES** via GitHub **OIDC → IAM role** (no static keys) |
| Recipients | **Per-repo configurable** via `.security/config.yml`; central security inbox **always CC'd** |
| System 1 scope | Secrets (**Gitleaks**) + SAST (**Semgrep**) + SCA (**Trivy fs**) + IaC/container (**Trivy config**) |
| System 1 gating | **Report-only**, email always (rollout phase). Fail-on-High threshold wired but off by default |
| System 2 catalog | Bumblebee's own `threat_intel/*.json` catalogs, pulled at runtime, **pinned to a verified commit** (`config/catalog-pin.txt`), bumped via PR |
| System 3 state | **Persist a snapshot manifest** to a dedicated state branch (`secinfra/manifests`, keyed `manifests/<branch>.json`) via git plumbing; diff against the prior version. No default-branch push — survives PR protection |
| System 3 policy | **Report all** new deps + detected license/SPDX ID, grouped by ecosystem. No allow/deny verdicts |
| System 3 ecosystems | **npm, Python (pip/poetry), Java (Maven/Gradle)** only |
| System 3 license tools | **Per-ecosystem tools** (not SBOM): `license-checker-rseidelsohn`, `pip-licenses`, Maven/Gradle license plugin |
| System 3 resolve mode | **Install dependencies, then detect** (most accurate) |
| Credential isolation | **Two-job pattern** per system: install/scan runs credential-less; a separate minimal job sends mail (and, for System 3, persists the manifest to the state branch) |
| Glue language | **Python** (boto3 for SES, JSON/SARIF parsing, Jinja2 HTML email) |

## 3. Universal architecture: two-job pattern

Every system is split into two jobs so that **untrusted code never shares a job with
mail or write credentials** — central to the supply-chain mandate.

1. **`scan` job**
   - Runs the tools (System 3 installs project dependencies, which executes arbitrary
     install scripts — hence the isolation).
   - **No SES role, no `id-token: write`, read-only `contents` token.**
   - Emits normalized results as a workflow **artifact** (JSON).
2. **`notify` job** (`needs: scan`)
   - Runs **no project/tool code**. Downloads the artifact, renders the email
     (Python + Jinja2), assumes the OIDC → SES role, sends.
   - For **System 3 only**, also holds `contents: write` to push the refreshed
     manifest to the dedicated state branch (`secinfra/manifests`) via git plumbing.
   - The **only** job that touches credentials.

## 4. Repository layout (this repo)

```
.github/workflows/
  security-scan.yml        # workflow_call — System 1 (scan + notify jobs)
  bumblebee-scan.yml       # workflow_call — System 2 (scan + notify jobs)
  license-tracker.yml      # workflow_call — System 3 (scan + notify jobs)
  self-test.yml            # CI for THIS repo: lint, unit tests, dry-run each system
scripts/secinfra/          # installable Python package
  common/
    config.py              # load + validate .security/config.yml
    sarif.py               # normalize SARIF/JSON from each tool
    mailer.py              # OIDC-assumed SES send (dry-run flag)
    render.py              # Jinja2 HTML+text rendering
    github.py              # run links, repo metadata, state-branch manifest helpers
  security_report.py       # aggregate Gitleaks + Semgrep + Trivy -> summary model
  bumblebee_report.py      # run bumblebee + catalogs -> summary model
  license_report.py        # per-ecosystem detect + diff vs prior manifest
templates/
  base.html.j2, base.txt.j2
  security.html.j2, bumblebee.html.j2, license.html.j2
config/
  catalog-pin.txt          # bumblebee commit SHA (supply-chain integrity)
  defaults/                # default Semgrep ruleset ref, Gitleaks + Trivy config
examples/
  caller-compliance.yml    # what an adopting repo drops in
  security-config.yml      # sample per-repo .security/config.yml
  cron-suggestions.md      # recommended (non-enforced) schedules
docs/
  PLAN.md                  # this document
  PREREQUISITES.md         # checklist the security team must complete
  ADOPTION.md              # team-facing import guide (added in Phase 3)
  OPERATIONS.md            # runbook: catalog bumps, role rotation, troubleshooting
pyproject.toml
```

## 5. How a team imports it

One thin caller workflow, pinned to a release tag, plus a config file. Cadence is
entirely the team's choice.

`.github/workflows/compliance.yml`:
```yaml
on:
  schedule: [{ cron: '0 6 * * *' }]     # team-chosen
  push: { branches: [main] }
  workflow_dispatch:
permissions:
  contents: write        # System 3 pushes its manifest to the state branch
  id-token: write        # OIDC -> SES in the notify jobs
jobs:
  security:
    uses: ignitesol/ignitesol.security-infra/.github/workflows/security-scan.yml@v1
    secrets: inherit
  licenses:
    uses: ignitesol/ignitesol.security-infra/.github/workflows/license-tracker.yml@v1
    secrets: inherit
  bumblebee:
    uses: ignitesol/ignitesol.security-infra/.github/workflows/bumblebee-scan.yml@v1
    secrets: inherit
```

`.security/config.yml`:
```yaml
email:
  to: [team-payments@ignitesol.com]    # security@ always CC'd by the workflow
systems:
  security: true
  bumblebee: true
  license: true
license:
  ecosystems: [npm, python, java]
  install:                              # optional per-ecosystem overrides
    npm: "npm ci --ignore-scripts"
    python: "pip install -r requirements.txt"
    java: "mvn -q dependency:resolve"
```

## 6. System 1 — Security scan

- **scan job** (read-only/static, low risk):
  - **Gitleaks** — secrets / committed credentials.
  - **Semgrep** — SAST across languages, central ruleset from `config/defaults/`.
  - **Trivy `fs`** — dependency CVEs (SCA).
  - **Trivy `config`** — IaC / Dockerfile / Kubernetes misconfiguration.
  - Each tool's SARIF/JSON normalized to a unified finding model
    (`tool, severity, file:line, rule, title`) -> artifact.
- **notify job:** one unified HTML+text email — per-category counts, top findings,
  run link, commit + timestamp.
- **Gating:** report-only (job stays green). Fail-on-High/Critical threshold is wired
  but disabled by default for the rollout phase.

## 7. System 2 — Bumblebee

- **scan job:**
  - `go install github.com/perplexityai/bumblebee/cmd/bumblebee@<pinned>` per
    `config/catalog-pin.txt`.
  - Fetch the same commit's `threat_intel/*.json` exposure catalogs.
  - Run a `project` scan over the workspace, passing every catalog via
    `--exposure-catalog`.
  - Parse NDJSON for `finding` records -> artifact.
- **notify job:** email "N components scanned / M exposure matches", listing matched
  package · version · campaign.
- **Catalog currency:** pinned commit is bumped via PR in this repo after review, so
  "kept current" stays under security-team control.

## 8. System 3 — License / dependency tracker

Ecosystems: **npm, Python, Java**. Mode: **install then detect**.

- **scan job (credential-less, isolated):**
  - Per ecosystem, run the team's install then the detector:
    - **npm** → `npm ci` → `license-checker-rseidelsohn`.
    - **Python** → `pip install` / `poetry install` → `pip-licenses`.
    - **Java** → Maven/Gradle resolve → license plugin.
  - Each ecosystem runs **independently**; a failed install degrades gracefully
    (reported as "could not resolve") without killing the others.
  - Install commands overridable in `.security/config.yml`.
  - Produces the current dependency + license manifest -> artifact.
- **notify job (`contents: write` + SES, no project code):**
  - Read the prior manifest from the **dedicated state branch** (`secinfra/manifests`,
    override via `SECINFRA_STATE_BRANCH`), keyed by source branch:
    `manifests/<source-branch>.json`. Absent branch/file ⇒ first run (empty baseline).
  - Diff current vs prior; email **dependencies added since last run**, each with
    detected license + SPDX ID, grouped by ecosystem. **Report all, no policy verdicts.**
  - Persist the refreshed manifest back to the state branch via **pure git plumbing**
    (`hash-object` → `update-index` on a temp index → `write-tree` → `commit-tree` →
    `push … :refs/heads/secinfra/manifests`). The working tree and default branch are
    never touched, so this survives PR-required branch protection. Git history on the
    state branch is the audit trail.

## 9. Email design

- Single Jinja2 base template -> branded **HTML + plaintext** fallback.
- Subject: `[<system>] <repo> — <N findings / new deps / matches>`.
- Body: summary table, top items, run link, scanned-at + commit.
- `mailer.py` assumes the OIDC role and calls SES `SendEmail`; `to` from repo config,
  `security@` hard-CC'd. **Dry-run flag** prints the rendered email instead of sending
  until prerequisites land.

## 10. Hardening (security mandate)

- All third-party actions and tool binaries **pinned by commit SHA**, checksum-verified.
- Bumblebee + catalogs pinned; bumps go through PR review here.
- OIDC role scoped to **`ses:SendEmail` only**, trust policy restricted to the
  `ignitesol` org + these workflows.
- **Credentials isolated** from any job that runs project/tool code (two-job pattern).
- System 3 installs run in a job with no SES/write creds; optional `--ignore-scripts`
  available per ecosystem if teams opt in.
- This repo scans itself via `self-test.yml`.

## 11. Prerequisites (security team) — see PREREQUISITES.md

1. Verified **SES sender identity/domain** (out of sandbox, or recipients verified).
2. **GitHub OIDC IAM role ARN** with `ses:SendEmail`, org-scoped trust -> org variable.
3. **Central security inbox** address (e.g. `security@ignitesol.com`).
4. This repo set **internal** so reusable workflows are callable org-wide.

## 12. Rollout

- **Phase 0** — scaffold repo, Python package, three two-job reusable workflows,
  templates, example caller + config; SES in **dry-run** mode.
- **Phase 1** — Systems 1 + 3 on 2–3 pilot repos; verify emails end to end.
- **Phase 2** — add System 2 (bumblebee); harden; tag **`v1`**.
- **Phase 3** — org-wide adoption guide (`ADOPTION.md`); optional opt-in upgrades
  (fail-on-High threshold, auto-open issues, license policy tiers) — designed-in, off
  by default.

## 13. Open / future (designed-in, not in v1)

- Fail-on-severity gating for System 1.
- Auto-open / update GitHub tracking issues.
- License risk tiers (allow / review / deny).
- Central rollup dashboard beyond the always-CC'd inbox.
