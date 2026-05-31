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

Or add a path-level ignore in `config/defaults/.semgrepignore` (affects all adopters)
or in the caller repo's own `.semgrepignore` file.

### Gitleaks (secrets scan)

Add an allowlist entry to the caller repo's `.gitleaks.toml`:

```toml
[[allowlist.regexes]]
description = "Test fixture — not a real secret"
regex = '''EXAMPLE_FAKE_KEY_[A-Z0-9]+'''
```

Or suppress inline with a `# gitleaks:allow` comment on the affected line.

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
