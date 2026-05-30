"""Send email via AWS SES, assuming an OIDC-issued role.

Set SECINFRA_DRY_RUN=1 to print the rendered email instead of sending.
The OIDC role assumption is handled externally by the workflow step
(aws-actions/configure-aws-credentials); this module uses whatever
credentials are active in the environment.
"""
from __future__ import annotations

import email.mime.multipart
import email.mime.text
import json
import os
import sys


def send(
    subject: str,
    html_body: str,
    text_body: str,
    to: list[str],
    cc: list[str],
    sender: str | None = None,
    region: str | None = None,
) -> None:
    from_addr = sender or os.environ.get("SECINFRA_SES_FROM", "security@ignitesol.com")
    aws_region = region or os.environ.get("SECINFRA_SES_REGION", "us-east-1")
    dry_run = os.environ.get("SECINFRA_DRY_RUN", "0").strip() not in ("0", "", "false", "False")

    all_recipients = list(dict.fromkeys(to + cc))

    if dry_run or not all_recipients:
        print("--- DRY RUN: email not sent ---", file=sys.stderr)
        print(f"From: {from_addr}", file=sys.stderr)
        print(f"To: {', '.join(to)}", file=sys.stderr)
        if cc:
            print(f"Cc: {', '.join(cc)}", file=sys.stderr)
        print(f"Subject: {subject}", file=sys.stderr)
        print("--- TEXT BODY ---", file=sys.stderr)
        print(text_body, file=sys.stderr)
        if not all_recipients:
            print("(no recipients configured — skipping)", file=sys.stderr)
        return

    import boto3

    client = boto3.client("ses", region_name=aws_region)

    msg = email.mime.multipart.MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = from_addr
    msg["To"] = ", ".join(to)
    if cc:
        msg["Cc"] = ", ".join(cc)

    msg.attach(email.mime.text.MIMEText(text_body, "plain", "utf-8"))
    msg.attach(email.mime.text.MIMEText(html_body, "html", "utf-8"))

    client.send_raw_email(
        Source=from_addr,
        Destinations=all_recipients,
        RawMessage={"Data": msg.as_bytes()},
    )
    print(f"Email sent to {all_recipients}", file=sys.stderr)
