# Prerequisites Checklist

Complete these before the systems can send real email or be adopted org-wide.
Until items 1–2 are done, all workflows run with the SES **dry-run** flag (the
rendered email is printed to the job log instead of being sent).

## 1. AWS SES sender identity
- [ ] Verify a sending **domain or address** in SES (e.g. `no-reply@ignitesol.com`).
- [ ] Move the SES account **out of sandbox**, OR verify each recipient address.
- [ ] Record the verified **From** address -> set as org variable `SECINFRA_SES_FROM`.
- [ ] Record the SES **region** -> org variable `SECINFRA_SES_REGION`.

## 2. GitHub OIDC -> IAM role for SES
- [ ] Ensure the GitHub OIDC provider exists in the AWS account
      (`token.actions.githubusercontent.com`).
- [ ] Create an IAM role whose **permissions policy allows only `ses:SendEmail`**
      (and `ses:SendRawEmail` if HTML multipart requires it).
- [ ] Restrict the role **trust policy** to the `ignitesol` org and, ideally, to these
      reusable workflows / approved repos.
- [ ] Record the role ARN -> org variable `SECINFRA_SES_ROLE_ARN`.

## 3. Recipients
- [ ] Confirm the **central security inbox** (e.g. `security@ignitesol.com`)
      -> org variable `SECINFRA_SECURITY_CC`. This address is CC'd on every email.
- [ ] Confirm teams know to set `email.to` in their `.security/config.yml`.

## 4. Repository / org settings
- [ ] Set this repo's visibility to **internal** so its reusable workflows are
      callable from other org repos.
- [ ] Decide the release tagging convention (`v1`, plus a moving `v1` major tag).
- [ ] Confirm org policy permits the required caller permissions
      (`contents: write` for System 3's manifest commit, `id-token: write` for OIDC).

## 5. Bumblebee pin
- [ ] Review the bumblebee commit to pin and record it in `config/catalog-pin.txt`.
- [ ] Agree on the cadence/owner for bumping the pin via PR (catalog currency).

## Org variables / secrets summary

| Name | Type | Purpose |
|---|---|---|
| `SECINFRA_SES_FROM` | variable | Verified SES From address |
| `SECINFRA_SES_REGION` | variable | SES region |
| `SECINFRA_SES_ROLE_ARN` | variable | OIDC-assumed IAM role (SES send only) |
| `SECINFRA_SECURITY_CC` | variable | Central security inbox, CC'd on all email |
