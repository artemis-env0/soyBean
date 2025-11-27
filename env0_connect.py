#!/usr/bin/env python3

"""
env0_connect.py
Author:
    artem@env0
    
Release Notes:
    - v0.0.2
    - Initial Release

Fixes:
    - Simplified Auth Process

Description:
    Shared helper module for env0 API authentication and configuration.

    Exposes:
      - get_env0_config() -> (api_base_uri, org_oid, headers)

Environment Variables:
    ENV0_API_URL             (optional, default: https://api.env0.com)
    ENV0_ORGANIZATION_ID     (required)
    ENV0_API_KEY             (required)
    ENV0_API_SECRET          (required)

Usage:
    from env0_connect import get_env0_config
    api_base_uri, org_oid, HEADERS = get_env0_config()
"""

import sys
import urllib3
import os
import base64 as b64


def get_env0_config():
    """
    Read env0-related environment variables and return:
    - api_base_uri
    - org_oid
    - headers (with Basic auth)
    """
    api_base_uri = os.environ.get("ENV0_API_URL", "https://api.env0.com")
    org_oid = os.environ["ENV0_ORGANIZATION_ID"]
    api_key = os.environ["ENV0_API_KEY"]
    api_secret = os.environ["ENV0_API_SECRET"]

    token = b64.b64encode(f"{api_key}:{api_secret}".encode("utf-8")).decode("ascii")
    headers = {
        "Authorization": f"Basic {token}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

    return api_base_uri, org_oid, headers
