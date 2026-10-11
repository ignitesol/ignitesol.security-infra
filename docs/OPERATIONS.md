# Operations Runbook

Reference for the security team maintaining `ignitesol/ignitesol.security-infra`.

---

## 1. Bumping the bumblebee catalog pin

The bumblebee threat-intel catalogs are pinned to a specific commit in
`config/catalog-pin.txt`. Bump this whenever a meaningful new catalog version is
released upstream.

**Process:**

1. Check upstream for new commits:
   ```bash
   git ls-remote https://github.com/perplexityai/bumblebee HEAD
   ```
2. Review the diff since the current pin — look at `threat_intel/*.json` changes:
   ```bash
   git -C /tmp/bumblebee-review diff <current-pin> <new-sha> -- threat_intel/
   ```
3. Open a PR updating `config/catalog-pin.txt` to the new SHA.
4. PR checklist before merging:
   - [ ] Reviewed threat_intel diff — no unexpected catalog removals
   - [ ] New catalogs (if any) are understood and expected
   - [ ] At least one team member has reviewed the diff
5. After merge, advance the moving `v1` tag:
   ```bash
   git tag -f -a v1 -m "secinfra v1 — bump bumblebee catalog to <new-sha>"
   git push origin v1 --force
   ```

Current pin is at `config/catalog-pin.txt`. All existing adoptions pick up the new
catalog automatically on their next run — no change required in caller repos.

---

## 2. Rotating the OIDC IAM role

The `SECINFRA_SES_ROLE_ARN` org variable points to the IAM role that GitHub Actions
assumes via OIDC to call `ses:SendEmail`. Rotate by replacing the role, not by
cycling a static key (there is no static key).

**Process:**

1. Create a new IAM role with the same trust policy and permission boundary as the
   existing role. Trust policy must allow `token.actions.githubusercontent.com` as
   OIDC provider, scoped to the `ignitesol` org.
2. Verify the new role can be assumed by running a manual `workflow_dispatch` on any
   adopted repo with `SECINFRA_SES_ROLE_ARN` temporarily set to the new ARN at the
   repo level (overrides org variable for that test).
3. Update the org variable `SECINFRA_SES_ROLE_ARN` to the new ARN.
4. Delete the old role after confirming a successful run with the new role.

No changes are needed to workflow files — the role ARN is consumed via the org
variable.

---

## 3. Debugging a failed OIDC assumption

**Symptom:** the "Configure AWS credentials" step fails with an auth error.

**Checklist:**

1. **Org variable set?** — confirm `SECINFRA_SES_ROLE_ARN` is set at the org level
   and is not empty. If missing, all runs fall through to dry-run mode silently.
2. **OIDC provider exists?** — in the AWS account, confirm
   `token.actions.githubusercontent.com` is registered as an Identity Provider.
3. **Trust policy condition** — the role's trust policy must match the calling repo.
   A common mistake is scoping to a specific repo name instead of the whole org.
   Recommended condition:
   ```json
   "StringLike": {
     "token.actions.githubusercontent.com:sub":
       "repo:ignitesol/*:*"
   }
   ```
4. **`id-token: write` permission** — the notify job in each reusable workflow
   already sets this. If a caller overrides the top-level `permissions:` block
   without including `id-token: write`, the OIDC token will not be issued.
5. **SES region mismatch** — `SECINFRA_SES_REGION` must match the region where the
   SES identity is verified.

**Quick test:** trigger a `workflow_dispatch` on an adopted repo and check the
"Configure AWS credentials" step output. A successful assumption prints the assumed
role ARN.

---

## 4. Handling false positives

### Semgrep (security scan)

Suppress a specific finding inline with a Semgrep comment on the affected line:

```python
result = eval(user_input)  # nosemgrep: dangerous-eval
```

Or add a `.semgrepignore` file to the **caller repo's root** (Semgrep reads it from
the directory it scans). There is no central ignore file.

### Gitleaks (secrets scan)

The workflow always runs with the central `config/defaults/gitleaks.toml`
(`--config` is explicit), so **a `.gitleaks.toml` in the caller repo is not read**.
What does work:

- **Inline:** add `# gitleaks:allow` to the affected line.
- **A known finding already in history:** add its fingerprint to a
  `.gitleaksignore` file in the caller repo root. The fingerprint
  (`<commit>:<file>:<rule>:<line>`) is in the run's `gitleaks.json` artifact.
- **A pattern that is a false positive everywhere:** open a PR against
  `config/defaults/gitleaks.toml`. Use `[[allowlists]]` (plural) for the array form;
  singular `[[allowlist]]` fails to load in gitleaks 8.30.x:

  ```toml
  [[allowlists]]
  description = "Test fixture — not a real secret"
  regexes = ['''EXAMPLE_FAKE_KEY_[A-Z0-9]+''']
  ```

If a secret is real, rotating it is the fix; suppressing it only silences the alert.

### Bumblebee (supply-chain scan)

Bumblebee matches against the threat-intel catalogs in `threat_intel/*.json`. If a
package name collides with a catalog entry but is a legitimate dependency:

1. Confirm the package origin is trusted (check npm/PyPI publish history, maintainer).
2. Document the exception in your repo's `.security/config.yml`:
   ```yaml
   bumblebee:
     ignore:
       - package: "some-package"
         reason: "Verified legitimate — not the malicious campaign variant"
   ```
   *(This field is reserved for a future version; currently the exception is
   documentation-only. The finding will still appear in the email.)*
3. If the catalog entry itself is a false positive across all repos, open a PR to
   `ignitesol/ignitesol.security-infra` with the catalog-pin bump notes.

---

## 5. General troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| Email not received, no error in logs | `SECINFRA_SES_ROLE_ARN` not set → dry-run mode | Set the org variable |
| Email not received, "Send email report" step failed | SES sandbox / unverified recipient | Verify recipient in SES or exit sandbox |
| bumblebee job fails with "exit code 2" | Scan found no output file | Ensure `results/bumblebee.ndjson` is pre-created (already fixed in v1) |
| license-tracker scan fails with "No package files found" | Ecosystem auto-detection missed a file | Set `ecosystems:` explicitly in the caller `with:` block |
| Scan job red, annotation "gitleaks/semgrep did not run correctly" | Scanner exited non-zero, wrote no/invalid output, or semgrep loaded 0 rules | Read the annotation and the step log; see §8. Notify and Gate still run and report the scan as incomplete |
| Gate fails with "scanner(s) did not run correctly" | Same as above; Gate fails closed once `fail_on` is set | Fix the scanner; do not lower `fail_on` to get green |
| SARIF upload fails | `security-events: write` missing from caller `permissions:` | Add to the caller workflow's top-level permissions |
| Manifest not written to state branch | `contents: write` missing, or branch protection covers all branches | Confirm `contents: write` in caller; the state branch `secinfra/manifests` should not be covered by branch-protection rules |

---

## 6. Keeping action SHAs current

All third-party actions in the reusable workflows are pinned to full commit SHAs
(org policy). GitHub will force Node.js 24 on actions from **June 16, 2026** —
update SHAs before that date. Process:

1. Look up the latest release SHA for each action (`gh release view --repo actions/checkout` etc.).
2. Open a PR updating all three workflow files + `self-test.yml`.
3. Advance the moving `v1` tag after merge (same as §1 step 5).

---

## 7. Adding a new ecosystem to System 3

The license tracker currently supports **npm**, **Python**, and **Java**. To add an
ecosystem:

1. Add detection logic in `scripts/secinfra/common/github.py` (or a new helper).
2. Add the install + detect script in the license-tracker scan job in
   `.github/workflows/license-tracker.yml`.
3. Update `examples/security-config.yml` and `docs/ADOPTION.md`.
4. Open a PR; once merged, bump `v1`.

---

## 8. Rollout: Gitleaks and Semgrep now actually run (behaviour change)

Until this change, two of the four scanners in `security-scan.yml` did nothing, and
`continue-on-error` hid it:

- **Gitleaks** — `config/defaults/gitleaks.toml` used `[[allowlist]]`, which gitleaks
  8.30.x rejects (`'AllowList' expected a map, got 'slice'`). It exited 1 and wrote
  no `gitleaks.json`, so secrets were never scanned and the gate's "secrets always
  fail" rule could never fire.
- **Semgrep** — `--config "p/default p/owasp-top-ten p/secrets"` was passed as one
  argument. Semgrep loaded 0 rules, exited 7 (swallowed by `|| true`) and wrote an
  empty SARIF in about 3 s.

Fixed by renaming the table to `[[allowlists]]` and passing one `--config` per
ruleset. Both scanners are now health-checked by `scripts/secinfra/scan_guard.py`, so
a scanner that fails to load its config or rules can no longer report a false
"clean".

### What consumers will see once `v1` moves

1. **Findings in the Notify email.** Gitleaks scans the full git history
   (`fetch-depth: 0`), so expect *historic* secrets, not just new ones. Semgrep
   findings use SARIF severity (`error` → high, `warning` → medium). Volume per repo
   is unknown until it runs; the email lists only the top 20.
2. **Secret values are redacted.** Gitleaks runs with `--redact` and
   `load_gitleaks_json` never copies `Match`/`Secret` into a finding, so the leaked
   text does not reach the artifact, run log or email. Emails show file, line, rule
   and a short commit SHA.
3. **Gate failures.** For any consumer that has set `systems.security.fail_on`, a
   single gitleaks finding now fails the gate (that rule existed but could never
   trigger), and Semgrep findings at or above the tier fail it too. Consumers with
   `fail_on: none` (the default) are unaffected.
4. **Gate fails closed on a broken scanner.** If gitleaks or semgrep did not run
   correctly, Gate fails (when `fail_on` is set) instead of passing on empty
   results. A transient failure such as the Semgrep registry being unreachable will
   therefore fail gated repos until re-run.
5. **Scan job goes red on a broken scanner.** Previously always green. Notify and
   Gate use `if: ${{ !cancelled() }}`, so they still run; the email carries an
   "incomplete scan" banner and the subject ends `SCANNER FAILED: <names>`. If Scan
   dies before the artifact upload (checkout or tool install fails), Notify and Gate
   now run and fail at the artifact download, where before they were skipped; a
   skipped required check counts as passing, so this fails closed.
6. **Scan job duration and billed minutes.** Semgrep previously cost about 3 s
   because it scanned with no rules. With rules loaded it downloads the rulesets and
   scans every tracked file: about 2 s on a one-file fixture (323 rules), growing
   with repo size and potentially minutes on large monorepos. Gitleaks adds a full-history scan. GitHub bills **per job, per whole
   minute**, so Scan going from under one minute to a few is a real cost increase on
   every scheduled run. There is no input to disable a scanner; the levers are
   `scan_root` (narrow the tree) and `semgrep_rules` (fewer rulesets,
   whitespace-separated, no spaces inside a ruleset name or path).

7. **Semgrep SARIF still contains matched source lines.** Semgrep writes
   `region.snippet.text` into `semgrep.sarif`, so a `p/secrets` hit places the
   matching line in the 7-day results artifact and, via the SARIF upload, in GitHub
   Code Scanning. Emails and logs are not affected (only the finding message is
   used). Gitleaks `--redact` does not cover this path. Strip snippets before upload
   if that exposure matters.

### Before the `v1` tag moves

1. **Measure.** In a test-bed repo and in the largest consumer, run the Compliance
   workflow against this branch and compare the Scan job's duration with a recent run
   on `@v1`:

   ```yaml
   uses: ignitesol/ignitesol.security-infra/.github/workflows/security-scan.yml@<branch>
   with:
     secinfra_ref: <branch>
   ```

2. **Tell consumers first.** Announce that secret and SAST findings, possible Gate
   failures and longer Scan runs are coming, and point them to §4 for suppressing
   false positives. Real secrets found in history must be rotated.
3. **Release mechanics.** The Scan job checks out `scripts/secinfra/scan_guard.py` and
   the fixed `gitleaks.toml` from `secinfra_ref`, whose default is this release's
   own tag. The release commit **must bump that default** to the new tag before it
   is tagged. Leaving it at `v1.1.1` makes every consumer's Scan fail at the guard
   step (the file does not exist there) and run the broken TOML.
4. Tag the release, then advance `v1` (§1 step 5).

**Rollback:** re-point `v1` at the previous release
(`git tag -f -a v1 <previous-sha> && git push origin v1 --force`). A consumer can
also pin `@v1.1.1` immediately.
