"""Draft supplier outreach email (client-side; no server upload)."""

from __future__ import annotations

from typing import Any


def draft_supplier_outreach_email(
    *,
    downstream_org_name: str,
    downstream_product_name: str,
    downstream_product_version: str | None,
    target_supplier_name: str,
    target_product_name: str,
    target_product_version: str | None,
    base_url: str = "https://streamingvex.org",
) -> dict[str, Any]:
    version_suffix = f" {target_product_version}" if target_product_version else ""
    downstream_ver = f" {downstream_product_version}" if downstream_product_version else ""
    subject = f"VEX publication request for {target_product_name}{version_suffix}"
    body = f"""Hello {target_supplier_name},

We are {downstream_org_name}, a downstream vendor shipping {downstream_product_name}{downstream_ver}.

We need CSAF/OpenVEX documents for {target_product_name}{version_suffix} published to StreamingVEX.

Supplier onboarding: {base_url.rstrip('/')}/ui/supplier-pusher

Thank you,
{downstream_org_name}
"""
    return {"subject": subject, "body": body}
