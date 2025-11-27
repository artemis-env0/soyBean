#!/usr/bin/env python3

"""
env0_soyBean_migrate.py
Author:
    artem@env0

Release Notes:
    - v1.0.0.1
    - Initial Release

Fixes:
    - Improved Performance

Description:
    Utility script to mass-update env0 templates (blueprints) so that
    their IaC tool is switched from Terraform to OpenTofu.

    The script:
      - Authenticates to env0 using API key/secret (via env0_connect.get_env0_config)
      - Lists all templates in the given organization
      - Filters templates currently using Terraform
      - In DRY-RUN mode: prints what would be changed
      - In APPLY mode: updates the tool field to 'opentofu'

Requirements:
    - Python 3.x
    - requests

Environment Variables:
    ENV0_API_URL             (optional, default: https://api.env0.com)
    ENV0_ORGANIZATION_ID     (required)
    ENV0_API_KEY             (required)
    ENV0_API_SECRET          (required)

Config Flags:
    DRY_RUN                  When True, no changes are made, only printed.
    TERRAFORM_TOOL_FIELD     JSON field name that stores the IaC tool type
                             (replace placeholder with the real field name).

Usage:
    # Dry run (recommended first run)
    $ python env0_soyBean_migrate.py

    # Edit the script to set DRY_RUN = False, then:
    $ python env0_soyBean_migrate.py

Notes:
    - Verify TERRAFORM_TOOL_FIELD by calling GET /blueprints/{id}
      and locating the field that currently equals 'terraform'.
    - Test against non-production templates before running in APPLY mode.
"""

import requests
import os
import sys
import urllib3
import base64 as b64
from env0_connect import get_env0_config

# ---------- env0 config (from shared auth lib) ----------
BASE_URL, ORG_ID, HEADERS = get_env0_config()

# ------------------------ config ------------------------
DRY_RUN = True  # set to False to actually update
TERRAFORM_TOOL_FIELD = "terraformTools"  # replace with real field name from GET /blueprints/{id} [Endpoint]
TARGET_TOOL = "opentofu"                 # desired value; valid values: 'opentofu', 'terraform'


def env0_get_all_templates():
    """
    Fetch all templates (blueprints) for the organization.
    The exact pagination keys may vary; if your org is small this might just return a flat list.
    """
    templates = []
    page = 0

    while True:
        resp = requests.get(
            f"{BASE_URL}/blueprints",
            headers=HEADERS,
            params={
                "organizationId": ORG_ID,
                "page": page,
                "limit": 100,
            },
            timeout=30,
        )
        resp.raise_for_status()
        data = resp.json()

        # Some env0 endpoints wrap results; others just return a list.
        if isinstance(data, list):
            docs = data
        else:
            docs = data.get("documents", data)

        if not isinstance(docs, list) or not docs:
            break

        templates.extend(docs)
        if len(docs) < 100:
            break
        page += 1

    return templates


def env0_update_template_tool(template, new_tool):
    """
    Update a single template's Terraform/OpenTofu tool.

    NOTE: If the API requires a full object instead of a partial update,
    you may need to send back all fields from `template`, just with the tool field changed.
    """
    tpl_id = template["id"]
    name = template.get("name")
    current = template.get(TERRAFORM_TOOL_FIELD)

    print(f"Updating template '{name}' ({tpl_id}): {current} -> {new_tool}")

    body = {
        # minimal payload: only change the tool field
        TERRAFORM_TOOL_FIELD: new_tool
    }

    resp = requests.put(
        f"{BASE_URL}/blueprints/{tpl_id}",
        headers=HEADERS,
        json=body,
        timeout=30,
    )
    resp.raise_for_status()


def env0_ignite():
    templates = env0_get_all_templates()
    print(f"Found {len(templates)} templates in org {ORG_ID}")

    to_change = [
        t for t in templates
        if t.get(TERRAFORM_TOOL_FIELD) == "terraform"
    ]

    print(f"{len(to_change)} templates currently using Terraform (will switch to {TARGET_TOOL})")

    for t in to_change:
        name = t.get("name")
        tpl_id = t.get("id")
        current = t.get(TERRAFORM_TOOL_FIELD)

        prefix = "[DRY-RUN]" if DRY_RUN else "[APPLY]"
        print(f"{prefix} {name} ({tpl_id}): {current} -> {TARGET_TOOL}")

        if not DRY_RUN:
            env0_update_template_tool(t, TARGET_TOOL)


if __name__ == "__main__":
    env0_ignite()
