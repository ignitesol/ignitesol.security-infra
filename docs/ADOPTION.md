# Adopting IgniteSol Security & Compliance

This guide takes an engineering team from zero to running automated security scans,
supply-chain checks, and license tracking — with emailed summaries — in under ten
minutes.

---

## What you get

| System | What it does | Cadence |
|---|---|---|
| **Security scan** | Secrets (Gitleaks), SAST (Semgrep), SCA + IaC (Trivy) | Daily recommended |
| **Bumblebee** | Supply-chain exposure scan against threat-intel catalogs | Weekly recommended |
| **License tracker** | Diffs new dependencies vs last run; emails SPDX license list | Daily recommended |

All three email a summary to your team's address and CC the central security inbox.
No findings = clean-bill email. Nothing is blocked by default; gating is opt-in.

---

## Prerequisites

The org-level variables (`SECINFRA_SES_FROM`, `SECINFRA_SES_REGION`,
`SECINFRA_SES_ROLE_ARN`, `SECINFRA_SECURITY_CC`) must be set before emails can be
sent. Until then, all runs execute in **dry-run mode** — the rendered email is printed
to the job log rather than sent, so you can validate the workflow without any AWS
setup.

Check `docs/PREREQUISITES.md` for the full setup checklist.

---

## Fast path — secinfra-onboard CLI

Install the CLI once:

```bash
pip install git+https://github.com/ignitesol/ignitesol.security-infra.git
```

Then, from inside the repo you want to onboard:

```bash
# Preview what would be generated (no files written)
secinfra-onboard --dry-run

# Write files and open a PR
secinfra-onboard --open-pr
```

The CLI auto-detects your ecosystems (npm / Python / Java), writes
`.github/workflows/compliance.yml` and `.security/config.yml`, and optionally opens
the adoption PR. Review the PR, set `email.to` in `.security/config.yml`, and merge.

### Scan your whole workspace

```bash
secinfra-onboard --scan-workspace /path/to/workspace
```

Prints a table of every local repo with onboarding status, config presence, and
detected ecosystems — useful for planning a batch rollout.

---

## Manual path

If you prefer not to use the CLI, copy the two files manually.

**`.github/workflows/compliance.yml`** — paste and adjust triggers:

```yaml
name: Compliance

on:
  push:
    branches: [main]
  workflow_dispatch:
  schedule:
    - cron: '0 6 * * *'    # nightly at 06:00 UTC

permissions:
  contents: write        # license-tracker writes dependency manifest
  id-token: write        # OIDC → SES in notify jobs
  security-events: write # upload SARIF to GitHub Code Scanning

jobs:
  security:
    uses: ignitesol/ignitesol.security-infra/.github/workflows/security-scan.yml@v1
    secrets: inherit

  licenses:
    uses: ignitesol/ignitesol.security-infra/.github/workflows/license-tracker.yml@v1
    secrets: inherit
    with:
      ecosystems: npm,python   # adjust to your repo

  bumblebee:
    uses: ignitesol/ignitesol.security-infra/.github/workflows/bumblebee-scan.yml@v1
    secrets: inherit
```

**`.security/config.yml`** — set your team's recipient address:

```yaml
email:
  to:
    - team-your-name@ignitesol.com

systems:
  security: true
  bumblebee: true
  license: true
```

See `examples/security-config.yml` for all available options.

---

## Choosing a cadence

See `examples/cron-suggestions.md` for copy-paste schedule options. The recommended
starting point is:

- **Nightly** — security scan + license tracker (push to main + cron `0 6 * * *`)
- **Weekly** — bumblebee (cron `0 6 * * 1`, Monday mornings)

Teams can also split into two workflow files (`compliance-daily.yml` /
`compliance-weekly.yml`) if they want different triggers per system.

---

## Opting into stricter gating

By default all systems are report-only. To fail the workflow on high-severity
findings, add to `.security/config.yml`:

```yaml
systems:
  security:
    fail_on: high    # options: critical | high | medium
```

---

## Adding a compliance badge

Once the workflow is live, add a status badge to your repo's `README.md`:

```markdown
[![Compliance](https://github.com/ignitesol/<YOUR-REPO>/actions/workflows/compliance.yml/badge.svg)](https://github.com/ignitesol/<YOUR-REPO>/actions/workflows/compliance.yml)
```

Replace `<YOUR-REPO>` with your repository name.

---

## Getting help

Open an issue or ping the security team. The runbook for operators (catalog bumps,
role rotation, troubleshooting) is in `docs/OPERATIONS.md`.
