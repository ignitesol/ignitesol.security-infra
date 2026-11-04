"""Did the scan job that feeds a gate actually succeed?

The reusable workflows run each Gate job with `if: ${{ !cancelled() }}` and
hand it `needs.scan.result` as SECINFRA_SCAN_RESULT. Without that, a failed
scan job would make GitHub *skip* the Gate job, and a skipped required check
counts as passing, so a scan that never produced results would let the merge
through. A gate that has opted in to blocking treats a non-success scan as a
failure.
"""
from __future__ import annotations

import os
from collections.abc import Mapping

ENV_VAR = "SECINFRA_SCAN_RESULT"


def scan_job_failed(env: Mapping[str, str] | None = None) -> bool:
    """True when the workflow reported the scan job as anything but success.

    Unset (local runs, tests) means unknown and is treated as success.
    """
    result = (env if env is not None else os.environ).get(ENV_VAR, "").strip()
    return bool(result) and result != "success"
