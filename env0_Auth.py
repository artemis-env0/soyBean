#!/usr/bin/env python3
"""
env0_Auth.py
Author:
    artem@env0
    
Release Notes:
    - v0.0.1b
    - Initial Release

Fixes:
    - Simplified Auth Process

Description:
    Shared helper module for env0 API authentication and configuration.

    Exposes:
      - get_env0_config() -> (base_url, org_id, headers)

Environment Variables:
    ENV0_API_URL             (optional, default: https://api.env0.com)
    ENV0_ORGANIZATION_ID     (required)
    ENV0_API_KEY             (required)
    ENV0_API_SECRET          (required)

Usage:
    from env0_auth import get_env0_config
    BASE_URL, ORG_ID, HEADERS = get_env0_config()
"""


import os
import base64 as b64


def get_env0_config():
    """
    Read env0-related environment variables and return:
    - base_url
    - org_id
    - headers (with Basic auth)
    """
    base_url = os.environ.get("ENV0_API_URL", "https://api.env0.com")
    org_id = os.environ["ENV0_ORGANIZATION_ID"]
    api_key = os.environ["ENV0_API_KEY"]
    api_secret = os.environ["ENV0_API_SECRET"]

    token = b64.b64encode(f"{api_key}:{api_secret}".encode("utf-8")).decode("ascii")
    headers = {
        "Authorization": f"Basic {token}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

    return base_url, org_id, headers
