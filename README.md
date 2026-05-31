# ignitesol.security-infra

Central home for IgniteSol's reusable security and compliance GitHub Actions workflows.
Any engineering team can import one of the three systems below in a few lines — no
per-repo setup beyond a config file.

> **Status:** Phase 1 complete. Systems 1 and 3 are live on pilot repos. See
> [docs/PLAN.md](docs/PLAN.md) for full implementation history and next steps.

---

## The three systems

| System | What it does | Workflow |
|---|---|---|
| **1 · Security scan** | Secrets (Gitleaks) · SAST (Semgrep) · SCA + IaC (Trivy) — one HTML email with findings grouped by severity | `security-scan.yml` |
| **2 · Bumblebee** | Supply-chain exposure scan using perplexityai/bumblebee threat-intel catalogs | `bumblebee-scan.yml` |
| **3 · License tracker** | Diffs your dependency manifest since the last run; emails new packages and their SPDX license IDs, grouped by ecosystem | `license-tracker.yml` |

All three email a summary via AWS SES at the end of every run, and each follows the
same **two-job pattern**: a credential-less `scan` job runs the tools, then a minimal
`notify` job assumes the OIDC role and sends the email. Credentials are never present
in any job that runs untrusted install or tool code.

---

## Onboarding a repo (fastest path)

Install the `secinfra` scripts, then run the onboard CLI:

```bash
# 1. Install (from this repo root)
pip install .

# 2. Preview what will be generated
secinfra-onboard --repo ../your-repo --email team@ignitesol.com --dry-run

# 3. Write files + open a GitHub PR in one step
secinfra-onboard --repo ../your-repo --email team@ignitesol.com --open-pr
```

The tool auto-detects ecosystems from your repo layout (`package.json` → npm,
`pyproject.toml` / `requirements.txt` → python, `pom.xml` / `build.gradle` → java)
and writes two files:

| File | Purpose |
|---|---|
| `.github/workflows/compliance.yml` | Calls the three reusable workflows |
| `.security/config.yml` | Team email, enabled systems, ecosystem list |

### Scan your whole workspace first

```bash
secinfra-onboard --scan-workspace ~/workspace
```

Prints a table of every local git repo showing whether it already has the compliance
workflow, the detected ecosystems, and the `.security/config.yml` status.

### onboard flags

| Flag | What it does |
|---|---|
| `--repo PATH` | Target repo path (default: `.`) |
| `--email ADDR` | `to:` address in `.security/config.yml` |
| `--ecosystems npm,python` | Override auto-detection |
| `--systems security,licenses` | Enable a subset of the three systems |
| `--ref v1` | Pin to a release tag instead of `main` |
| `--schedule '0 6 * * *'` | Add a nightly cron trigger |
| `--dry-run` | Print files without writing |
| `--force` | Overwrite existing files |
| `-y` | Skip all interactive prompts |
| `--branch` | Create `secinfra/compliance-setup` branch and commit |
| `--open-pr` | Branch + commit + push + open GitHub PR (`gh` CLI required) |
| `--branch-name NAME` | Override the branch name |
| `--scan-workspace DIR` | Status table for every repo under DIR |

---

## Manual adoption (without the CLI)

If you prefer to write the files by hand, copy from the examples:

**`.github/workflows/compliance.yml`**
```yaml
name: Compliance

on:
  push:
    branches: [main]
  workflow_dispatch:
  # schedule:
  #   - cron: '0 6 * * *'   # uncomment for nightly runs

permissions:
  contents: write        # System 3 — persist dependency manifest to state branch
  id-token: write        # OIDC → SES in the notify jobs
  security-events: write # System 1 — upload SARIF to GitHub Code Scanning

jobs:
  security:
    uses: ignitesol/ignitesol.security-infra/.github/workflows/security-scan.yml@main
    secrets: inherit

  licenses:
    uses: ignitesol/ignitesol.security-infra/.github/workflows/license-tracker.yml@main
    secrets: inherit
    with:
      ecosystems: "npm,python"   # adjust to your repo

  bumblebee:
    uses: ignitesol/ignitesol.security-infra/.github/workflows/bumblebee-scan.yml@main
    secrets: inherit
```

**`.security/config.yml`**
```yaml
email:
  to:
    - your-team@ignitesol.com   # security@ is always CC'd automatically

systems:
  security: true
  bumblebee: true
  license: true

license:
  ecosystems:
    - npm
    - python
    # - java

paths:
  scan_root: "."
```

See [`examples/cron-suggestions.md`](examples/cron-suggestions.md) for recommended
schedules.

---

## Org prerequisites

These are set **once** by the security team — no per-repo action needed.

| Org variable | Purpose |
|---|---|
| `SECINFRA_SES_FROM` | Verified SES From address (`no-reply@ignitesol.com`) |
| `SECINFRA_SES_REGION` | SES region (default: `us-east-1`) |
| `SECINFRA_SES_ROLE_ARN` | OIDC-assumed IAM role (ses:SendEmail only) |
| `SECINFRA_SECURITY_CC` | Central security inbox — CC'd on every email |

If `SECINFRA_SES_ROLE_ARN` is absent or empty, all workflows automatically run in
**dry-run mode**: the email is rendered and printed to the job log but not sent. This is
safe on first adoption while the org secrets are being confirmed.

Full setup checklist: [docs/PREREQUISITES.md](docs/PREREQUISITES.md).

---

## Installing the scripts

The `secinfra` Python package lives in `scripts/`. It is installed by the reusable
workflows automatically (`pip install .secinfra/`), but you can also install it locally
for development or to run the onboard CLI.

```bash
# Standard install
pip install .

# Editable install for development
pip install -e ".[dev]"

# The CLI is then available as:
secinfra-onboard --help
```

**Requirements:** Python ≥ 3.11. Dependencies are listed in `pyproject.toml`:
`boto3`, `jinja2`, `pyyaml`, `packaging`.

---

## Development

```bash
# Install with dev extras (pytest, ruff)
pip install -e ".[dev]"

# Lint
ruff check scripts/

# Tests
pytest

# Preview a security report email without sending (set DRY_RUN)
SECINFRA_DRY_RUN=1 python -m secinfra.security_report --results-dir results/

# Preview a license report email
SECINFRA_DRY_RUN=1 python -m secinfra.license_report --results-dir results/ --workspace .
```

---

## How it works — System 3 dependency manifest

The license tracker diffs your current dependencies against the last recorded snapshot.
The snapshot is stored on a dedicated **`secinfra/manifests`** branch in your repo
(auto-created on first run), keyed by source branch:

```
secinfra/manifests
└── manifests/
    ├── main.json
    └── dev.json
```

This branch is never protected and is written via pure git plumbing — no commits touch
your default branch and no pull request is required. Override the branch name with the
`SECINFRA_STATE_BRANCH` environment variable.

---

## Repository layout

```
.github/workflows/
  security-scan.yml      # reusable — System 1
  bumblebee-scan.yml     # reusable — System 2
  license-tracker.yml    # reusable — System 3
  self-test.yml          # CI for this repo

scripts/secinfra/        # installable Python package
  common/
    config.py            # .security/config.yml loader
    sarif.py             # SARIF / tool JSON normaliser
    mailer.py            # SES send with OIDC assumption + dry-run
    render.py            # Jinja2 HTML + plaintext rendering
    github.py            # run metadata; state-branch manifest helpers
  templates/             # Jinja2 email templates (8 files)
  security_report.py     # System 1 notify entry point
  bumblebee_report.py    # System 2 notify entry point
  license_report.py      # System 3 notify entry point
  onboard.py             # secinfra-onboard CLI

config/
  catalog-pin.txt        # bumblebee commit SHA (supply-chain pin)
  defaults/              # default Semgrep ruleset, Gitleaks + Trivy config

examples/
  caller-compliance.yml  # drop-in caller workflow template
  security-config.yml    # sample .security/config.yml
  cron-suggestions.md    # recommended cron schedules

docs/
  PLAN.md                # implementation history, decisions, phase status
  PREREQUISITES.md       # org setup checklist
```

---

## Operations

**Bumping the bumblebee catalog pin**

```bash
# Find the latest bumblebee commit
git ls-remote https://github.com/perplexityai/bumblebee HEAD

# Update the pin
echo "<new-sha>" > config/catalog-pin.txt
git commit -m "chore: bump bumblebee catalog pin to <short-sha>"
# Open a PR — the security team reviews before merge
```

**Debugging a failed OIDC assumption**

1. Check that `SECINFRA_SES_ROLE_ARN` is set as an org variable (not a secret, not
   repo-level).
2. Verify the IAM role trust policy includes
   `token.actions.githubusercontent.com` as the OIDC provider.
3. The trust condition should allow `repo:ignitesol/*:*` (or a more specific ref).
4. The notify job's `if:` reads `env.SECINFRA_SES_ROLE_ARN`, which is promoted to the
   **job-level** `env:` block — if it's missing there, the AWS step is silently skipped.

---

## License

MIT — see [LICENSE](LICENSE).
