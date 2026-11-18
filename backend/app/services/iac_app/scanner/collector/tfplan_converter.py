"""Converter for Terraform plan binary files to JSON.

Converts .tfplan binary files to JSON using `terraform show -json <plan>`.
Falls back gracefully if terraform CLI is not available.
"""

import json
import logging
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)


class TfPlanConversionError(Exception):
    """Raised when Terraform plan conversion fails."""


def convert_tfplan_to_json(tfplan_path: str | Path) -> dict:
    """Convert a .tfplan binary file to a JSON dict.

    Uses `terraform show -json <plan>` to convert the binary plan.

    Args:
        tfplan_path: Path to the .tfplan binary file.

    Returns:
        Parsed JSON dict of the Terraform plan.

    Raises:
        TfPlanConversionError: If conversion fails.
        FileNotFoundError: If the plan file does not exist.
    """
    plan_path = Path(tfplan_path)

    if not plan_path.exists():
        raise FileNotFoundError(f"Terraform plan file not found: {plan_path}")

    if not plan_path.suffix == ".tfplan":
        raise ValueError(f"Expected a .tfplan file, got: {plan_path.suffix}")

    if not _is_terraform_available():
        raise TfPlanConversionError(
            "Terraform CLI is not available. "
            "Install Terraform to enable .tfplan scanning."
        )

    try:
        result = subprocess.run(
            ["terraform", "show", "-json", str(plan_path)],
            capture_output=True,
            text=True,
            timeout=60,
            shell=False,
        )

        if result.returncode != 0:
            error_msg = result.stderr.strip() or "Unknown error"
            raise TfPlanConversionError(
                f"terraform show failed (exit code {result.returncode}): {error_msg}"
            )

        if not result.stdout.strip():
            raise TfPlanConversionError("terraform show returned empty output")

        return json.loads(result.stdout)

    except json.JSONDecodeError as e:
        raise TfPlanConversionError(f"Failed to parse terraform show output as JSON: {e}")
    except subprocess.TimeoutExpired:
        raise TfPlanConversionError("terraform show timed out after 60 seconds")
    except FileNotFoundError:
        raise TfPlanConversionError("terraform command not found")


def _is_terraform_available() -> bool:
    """Check if terraform CLI is available."""
    try:
        result = subprocess.run(
            ["terraform", "version"],
            capture_output=True,
            text=True,
            timeout=10,
            shell=False,
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired, subprocess.SubprocessError):
        return False
