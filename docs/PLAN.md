# IgniteSol Security & Compliance Infrastructure — Plan

> **Status:** Phase 2 complete (pending pilot PR merges). Phase 3 (org-wide adoption) is next.
> **Owner:** Chief Security & Compliance Engineering.
> **Repo:** `ignitesol/ignitesol.security-infra` — central home for reusable GitHub
> Actions workflows, orchestration scripts, email templates, and pinned threat-intel
> config.
> **Last updated:** 2026-05-31.

---

## 1. Mandate

Provide three systems that any engineering team can **import into their GitHub Actions
workflow** in a few lines and run regularly:

1. **Security scan** — secrets (Gitleaks), SAST (Semgrep), SCA + IaC (Trivy).
2. **Bumblebee** — supply-chain exposure scan via
   [perplexityai/bumblebee](https://github.com/perplexityai/bumblebee).
3. **License / dependency tracker** — diff dependencies added since the last run,
   grouped by ecosystem and license.

All three **email a summary** at the end via AWS SES.

---

## 2. Architecture decisions

| Area | Decision | Status |
|---|---|---|
| CI platform | GitHub Actions reusable workflows (`workflow_call`) | ✅ implemented |
| Cadence | Fully team-owned — caller sets cron/push/dispatch | ✅ implemented |
| Email transport | AWS SES via GitHub OIDC → IAM role (no static keys) | ✅ implemented |
| Recipients | Per-repo `.security/config.yml`; central CC always added | ✅ implemented |
| Credential isolation | Two-job pattern: scan (no creds) → notify (OIDC + optional write) | ✅ implemented |
| Glue language | Python — boto3 (SES), Jinja2 (HTML email), PyYAML, packaging | ✅ implemented |
| System 1 tools | Gitleaks 8.30.1 · Semgrep · Trivy 0.70.0 fs + config | ✅ implemented |
| System 1 gating | Report-only; fail-on-High wired but off by default | ✅ implemented |
| System 2 catalog | Bumblebee `threat_intel/*.json` pinned via `config/catalog-pin.txt` | ✅ implemented |
| System 3 ecosystems | npm · Python (pip/poetry) · Java (Maven/Gradle) | ✅ implemented |
| System 3 license tools | `license-checker-rseidelsohn` · `pip-licenses` · Maven license plugin | ✅ implemented |
| System 3 resolve mode | Install deps, then detect (most accurate) | ✅ implemented |
| System 3 state | Dedicated orphan state branch (`secinfra/manifests`) via git plumbing | ✅ implemented |
| Repo visibility | **Public** (required for cross-org `workflow_call` with default token) | ✅ — see §4 |
| Onboarding | `secinfra-onboard` CLI — auto-detects ecosystems, writes files, opens PR | ✅ implemented |
| Actions pinning | All third-party actions pinned to full commit SHA (org policy) | ✅ implemented |

---

## 3. Universal architecture: two-job pattern

Every system is split into two jobs so **untrusted code never shares a job with
credentials**.

```
┌─────────────────────────────────────────────┐
│  scan job  (permissions: contents: read)    │
│  • runs tools / installs project deps       │
│  • no SES role, no id-token: write          │
│  • emits normalized JSON artifact           │
└───────────────────┬─────────────────────────┘
                    │  artifact
┌───────────────────▼─────────────────────────┐
│  notify job  (needs: scan)                  │
│  • downloads artifact only                  │
│  • renders Jinja2 email → SES send          │
│  • System 3: also writes manifest to state  │
│    branch via git plumbing (contents:write) │
│  • the ONLY job that touches credentials    │
└─────────────────────────────────────────────┘
```

---

## 4. Implementation decisions & deviations

These were made during Phase 0–1 and represent permanent design choices.

### 4.1 Repo is public, not internal

**Original plan:** mark the repo `internal` so org repos can call its reusable
workflows.

**What actually happened:** `actions/checkout` with the default `GITHUB_TOKEN` returns
404 for internal repos when called from a different repo's workflow — the cross-repo
token does not get `contents: read` on `internal` repos.

**Decision:** made `ignitesol/ignitesol.security-infra` **public**. This is safe because
the repo contains no secrets, no customer data, and no private business logic — only
workflow definitions, open-source tool configs, and email templates.

### 4.2 State branch for the dependency manifest

**Original plan:** System 3 commits the refreshed dependency manifest back to the
caller repo's default branch (`[skip ci]` commit).

**What actually happened:** direct push to `dev`/`main` was rejected with GitHub's
`GH013` error because those branches require changes through a pull request.

**Decision:** persist the manifest to a **dedicated orphan branch** (`secinfra/manifests`
by default, override via `SECINFRA_STATE_BRANCH`). The manifest for each source branch
is stored at `manifests/<branch-name>.json`. Implementation uses pure git plumbing
(`hash-object` → `update-index` on a temporary `GIT_INDEX_FILE` → `write-tree` →
`commit-tree` → force-push to `refs/heads/secinfra/manifests`) — the working tree and
default branch are never touched. Git history on the state branch is the audit trail.

### 4.3 Tool version bumps

Gitleaks and Trivy versions in the original workflow (8.18.2 / 0.50.0) returned 404
on the GitHub Releases API at build time. Bumped to current stable:

| Tool | Original | Pinned |
|---|---|---|
| Gitleaks | 8.18.2 | **8.30.1** |
| Trivy | 0.50.0 | **0.70.0** |

### 4.4 setuptools build backend

`setuptools.backends.legacy` does not exist in setuptools ≥ 61. Fixed to
`setuptools.build_meta` with `requires = ["setuptools>=61"]`.

### 4.5 Template path fix

Templates were initially at repo root `templates/`, outside the Python package.
After `pip install`, the Jinja2 loader could not find them. Fixed by:
- Moving templates into `scripts/secinfra/templates/`
- Adding `[tool.setuptools.package-data] secinfra = ["templates/*.j2"]`
- Updating `render.py` path to `Path(__file__).parent.parent / "templates"`

### 4.6 OIDC step conditional

The `if: ${{ env.VAR != '' }}` on the AWS credentials step was evaluated before the
step's own `env:` block was applied, so the variable was always empty and the step was
silently skipped.

**Fix:** promoted `SECINFRA_SES_ROLE_ARN` to the **job-level** `env:` block in all
three notify jobs. The step's `if:` can now read it.

### 4.7 secinfra-onboard CLI (addition to original plan)

Not in the original plan. Added `scripts/secinfra/onboard.py` and `secinfra-onboard`
entry point to reduce the time it takes to bring a new repo into compliance:
- Auto-detects ecosystems from repo layout
- Writes `.github/workflows/compliance.yml` and `.security/config.yml`
- `--dry-run`, `--branch`, `--open-pr` modes
- `--scan-workspace` shows every local repo's onboarding status at a glance

---

## 5. Repository layout

```
.github/workflows/
  security-scan.yml        # reusable — System 1 (scan + notify jobs)
  bumblebee-scan.yml       # reusable — System 2 (scan + notify jobs)
  license-tracker.yml      # reusable — System 3 (scan + notify jobs)
  self-test.yml            # CI for this repo: lint + unit tests

scripts/secinfra/          # installable Python package (pip install .)
  common/
    config.py              # load + validate .security/config.yml
    sarif.py               # normalize SARIF / tool JSON → finding model
    mailer.py              # OIDC-assumed SES send; dry-run flag
    render.py              # Jinja2 HTML + plaintext rendering
    github.py              # run metadata; read_state_manifest / write_state_manifest
  templates/               # packaged Jinja2 templates (8 files)
    base.{html,txt}.j2
    security.{html,txt}.j2
    bumblebee.{html,txt}.j2
    license.{html,txt}.j2
  security_report.py       # System 1 notify entry point
  bumblebee_report.py      # System 2 notify entry point
  license_report.py        # System 3 notify entry point
  onboard.py               # secinfra-onboard CLI

config/
  catalog-pin.txt          # bumblebee commit SHA pinned for supply-chain integrity
  defaults/                # default Semgrep ruleset, Gitleaks + Trivy config

examples/
  caller-compliance.yml    # drop-in caller workflow template
  security-config.yml      # sample .security/config.yml
  cron-suggestions.md      # recommended (non-enforced) schedules

docs/
  PLAN.md                  # this document
  PREREQUISITES.md         # security-team setup checklist
```

---

## 6. Rollout phases

### Phase 0 — Scaffold ✅ complete
All workflows, Python package, templates, config, examples, and docs written and pushed
to `ignitesol/ignitesol.security-infra`. SES dry-run mode enabled until OIDC role is
present.

### Phase 1 — Pilot (Systems 1 + 3) ✅ complete

| Item | Status |
|---|---|
| Adoption PRs created for `ignite-email-service` and `fizzy-metrics` | ✅ |
| Email sending confirmed working end-to-end | ✅ |
| All runtime issues resolved (§4 above) | ✅ |
| `secinfra-onboard` CLI available for faster future adoption | ✅ |
| State-branch manifest persistence (no default-branch push) | ✅ |

Systems 1 (security scan) and 3 (license tracker) are live on both pilot repos.
System 2 (bumblebee) is disabled in the pilot `compliance.yml` pending Phase 2.

### Phase 2 — Bumblebee + v1 tag ✅ complete (pilot PRs pending merge)

| Item | Status |
|---|---|
| Enable bumblebee job in pilot `compliance.yml` files | ✅ PRs open — ignite-email-service#87, fizzy-metrics#3 |
| Verify bumblebee email end-to-end on at least one pilot | ✅ ignite-email-service dispatch run confirmed OIDC + SES send |
| Review catalog-pin.txt — bump if stale | ✅ current with upstream bumblebee HEAD (`7c93206`) |
| Tag `v1` on this repo + create a moving `v1` major tag | ✅ `v1.0.0` (immutable) + `v1` (moving) pushed |
| Update pilot workflows to reference `@v1` instead of `@main` | ✅ included in the same pilot PRs |

Merge ignite-email-service#87 and fizzy-metrics#3 to complete Phase 2.

### Phase 3 — Org-wide adoption 🔜 after v1

| Item | Status |
|---|---|
| Write `docs/ADOPTION.md` — team-facing import guide | ⬜ |
| Write `docs/OPERATIONS.md` — runbook (catalog bumps, role rotation, troubleshooting) | ⬜ |
| Announce to engineering leads; use `secinfra-onboard` for batch rollout | ⬜ |
| Add compliance status badge to each adopted repo's README | ⬜ |

**Phase 3 is still valid.** The `secinfra-onboard` CLI (added in Phase 1) makes the
batch rollout significantly faster than originally planned — a workspace scan + one
`--open-pr` per repo replaces the manual PR process. The `ADOPTION.md` should document
this workflow. `OPERATIONS.md` should cover:
- Bumping `catalog-pin.txt` (PR-based, with review checklist)
- Rotating the OIDC IAM role
- Debugging failed OIDC assumptions
- What to do when a bumblebee scan or Semgrep rule produces false positives

---

## 7. Designed-in, not in v1

These are wired for but off by default:

| Feature | Trigger to enable |
|---|---|
| Fail-on-High/Critical gating (System 1) | Set `systems.security.fail_on: high` in `.security/config.yml` |
| Auto-open GitHub tracking issues on new findings | Phase 3 opt-in; needs `issues: write` in caller |
| License risk tiers (allow / review / deny lists) | Phase 3 opt-in; config key `license.policy` |
| Central rollup dashboard | Post-Phase 3; aggregates the always-CC'd security inbox |

---

## 8. Org variables reference

Set at the **org level** — no per-repo secrets needed.

| Variable | Purpose |
|---|---|
| `SECINFRA_SES_FROM` | Verified SES From address |
| `SECINFRA_SES_REGION` | SES region (default: `us-east-1`) |
| `SECINFRA_SES_ROLE_ARN` | OIDC-assumed IAM role ARN (ses:SendEmail only) |
| `SECINFRA_SECURITY_CC` | Central security inbox; CC'd on every email |

Absent `SECINFRA_SES_ROLE_ARN` → all workflows run in **dry-run mode** (email rendered
to job log, not sent). Safe default for new repos before the org secrets are confirmed.
