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
  # Add this if you want to gate merges (see "Opting into stricter gating"
  # below) — push-to-main alone runs after the merge, too late to block it.
  # pull_request:
  #   branches: [main]

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

By default all systems are report-only — nothing blocks a merge until you opt in.
Each workflow now runs a third job, **Gate**, alongside `Notify` (both depend only
on `Scan`, so email delivery and gating never block each other). Gate reads the
same policy from `.security/config.yml` and exits non-zero when it's tripped;
report-only repos see it pass unconditionally.

### Security scan

```yaml
systems:
  security:
    fail_on: high    # none (default) | critical | high | medium | low
```

Findings at or above the configured tier fail the gate. **Gitleaks (secret)
findings always fail the gate once `fail_on` is set to any tier** — a checked-in
credential isn't something a noise-reduction threshold should be able to wave
through.

### Bumblebee

```yaml
systems:
  bumblebee:
    fail_on: any    # none (default) | any
```

Bumblebee's exposure records carry no documented severity taxonomy upstream, so
gating is boolean: any match against a threat-intel catalog fails the build.

### License tracker

```yaml
license:
  policy:
    deny: [GPL-3.0, AGPL-3.0, SSPL-1.0]   # SPDX ids/prefixes; empty by default
    deny_unknown: true                     # fail on missing/"Unknown" license
```

Unlike the report email (which only lists *newly added* dependencies), the gate
checks every dependency currently in the repo — so turning this on surfaces
existing violations immediately, not just future ones. There is no default
deny-list; license restrictions are a policy call each team makes explicitly.

### Making it actually block merges

Opting into `fail_on`/`policy` only makes the job fail — it doesn't block
anything by itself. Two more steps, both in the **consuming repo**:

1. Trigger the caller workflow on `pull_request` (the example in
   [Manual path](#manual-path) above only runs on `push` to `main`, i.e. after
   merge — add a `pull_request` trigger so it runs beforehand).
2. Add the relevant check(s) to branch protection / repo rulesets as **required
   status checks**. GitHub names a reusable-workflow check `<caller job id> /
   <called job name>` — with the job ids in `examples/caller-compliance.yml`
   (`security`, `bumblebee`, `licenses`) that's `security / Gate`,
   `bumblebee / Gate`, `licenses / Gate` (adjust if you renamed the jobs in
   your own `compliance.yml`).

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
