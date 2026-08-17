# Gating tier examples

Three worked examples of `.github/workflows/compliance.yml` +
`.security/config.yml` pairs, each showing a different combination of the
security-scan/license-tracker gate thresholds — see "Opting into stricter
gating" in [`docs/ADOPTION.md`](../ADOPTION.md) for the underlying mechanism.
One rule holds across all three: **bumblebee (supply chain) is always
`fail_on: any`** — every tier blocks merges on any exposure-catalog match,
with no report-only option. Security (SAST/SCA/IaC/secrets) and license
gating are the two axes that vary per repo.

| Tier | Repo | Security (`fail_on`) | License policy | Bumblebee |
|---|---|---|---|---|
| [Strict](chaturji-backend/) | ignitesol.chaturji.backend | `high` | deny GPL/AGPL/SSPL + deny_unknown | `any` |
| [Moderate](email-service/) | ignite-email-service | `critical` | deny AGPL/SSPL only | `any` |
| [Lenient](slack-service/) | ignite-slack-service | `none` (report-only) | off (report-only) | `any` |

The mapping follows blast radius, not repo size: chaturji-backend is the
flagship LLM/RAG product and touches payment-reporting code, so it gets the
tightest gate on all three systems; email-service is an internal
microservice where a small team needs to triage findings quickly, so it
only blocks on the severest tier; slack-service is a first-time onboarding
for a small internal integration, so it starts report-only everywhere
except supply chain and can tighten up once the team has seen a few runs.

## Two things to know before copying these

**`fail_on: none` also turns off the secrets carve-out.** Gitleaks (secret)
findings normally always fail the gate once `fail_on` is set to *any* real
tier, regardless of how lenient that tier is — but that carve-out only
triggers once gating is opted into at all. Under `fail_on: none` (the
slack-service example), a leaked credential will still show up in the
email report but will **not** fail the build. If you want secrets to always
block while staying lenient on SAST/SCA severity, the current
implementation can't express that split — the cheapest way to get it today
is to set `fail_on: critical` even if you don't expect to lean on the
severity threshold itself.

**A cron-only job can never be a required status check.** GitHub branch
protection can only require a check that ran on the pull request; a job
triggered solely by `schedule:` never attaches to a PR's check run.
ignitesol.chaturji.backend currently splits bumblebee into its own
cron-only `compliance-weekly.yml`, which is why the strict-tier example here
folds all three systems into one `pull_request`-triggered workflow instead —
"supply chain always blocks merge" requires bumblebee to run on every PR,
not just on Mondays. Keep a separate deep/weekly sweep alongside the
PR-triggered one if you still want it; just don't rely on it alone for
gating.

## Applying an example

1. Copy `compliance.yml` into the target repo's `.github/workflows/`.
2. Copy `security-config.yml` into the target repo's `.security/config.yml`,
   replacing the `email.to` placeholder.
3. In the repo's branch protection / ruleset, add the required status
   checks listed in the trailing comment of each `compliance.yml`. GitHub
   names a reusable-workflow check `<caller job id> / <called job name>` —
   with the job ids used here (`security`, `licenses`, `bumblebee`) that's
   `security / Gate`, `licenses / Gate`, `bumblebee / Gate`.

None of this has been applied to the three repos it's based on — these are
worked examples living in this repo, not a change to
ignitesol.chaturji.backend, ignite-email-service, or ignite-slack-service.
