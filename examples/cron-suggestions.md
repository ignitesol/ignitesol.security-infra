# Suggested Cron Schedules

These are non-enforced recommendations. Paste any of these into the `schedule:` block
of your caller `.github/workflows/compliance.yml`.

## Nightly security + license, weekly bumblebee (recommended starting point)

```yaml
on:
  schedule:
    - cron: '0 6 * * *'     # 06:00 UTC every night — runs security + license
  push:
    branches: [main]
  workflow_dispatch:
```

And then in your `bumblebee` job, add a condition so it only runs on Mondays:
```yaml
  bumblebee:
    if: github.event_name == 'workflow_dispatch' || github.event_name == 'schedule' && ... 
    uses: ignitesol/ignitesol.security-infra/.github/workflows/bumblebee-scan.yml@v1
    secrets: inherit
```

Or simply split into two workflow files: `compliance-daily.yml` (security + license)
and `compliance-weekly.yml` (bumblebee only).

## Split: daily vs weekly

**`.github/workflows/compliance-daily.yml`**
```yaml
on:
  schedule: [{ cron: '0 6 * * *' }]
  push: { branches: [main] }
  workflow_dispatch:
jobs:
  security:
    uses: ignitesol/ignitesol.security-infra/.github/workflows/security-scan.yml@v1
    secrets: inherit
  licenses:
    uses: ignitesol/ignitesol.security-infra/.github/workflows/license-tracker.yml@v1
    secrets: inherit
```

**`.github/workflows/compliance-weekly.yml`**
```yaml
on:
  schedule: [{ cron: '0 6 * * 1' }]   # 06:00 UTC every Monday
  workflow_dispatch:
jobs:
  bumblebee:
    uses: ignitesol/ignitesol.security-infra/.github/workflows/bumblebee-scan.yml@v1
    secrets: inherit
```

## Other common options

| Description | Cron |
|---|---|
| Nightly at 02:00 UTC | `0 2 * * *` |
| Every Monday at 08:00 UTC | `0 8 * * 1` |
| Every 6 hours | `0 */6 * * *` |
| First of each month | `0 9 1 * *` |
