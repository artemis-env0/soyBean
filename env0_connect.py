#!/usr/bin/env python3

"""
env0_connect.py
Author:
    artem@env0

Release Notes:
    - v1.0.0.3
    - Added multi-method authentication: GlobalEnv, UseKubeSecret (default), Base64, BuildKubeSecret
    - Added launch modes: Quiet, Interactive, Menu, Sandbox
    - Added Kubernetes provider switch: kubectl or kubernetes python client
    - Added verbose STDOUT logging and interactive validation workflows

Fixes:
    - Improved validation and error handling
    - Improved operational usability for Kubernetes-based credential delivery

Description:
    Shared helper module for env0 API authentication and configuration.

    Exposes:
      - get_env0_config() -> (api_base_uri, org_oid, headers)

Authentication (env0 API):
    Basic Authentication:
      Username: API Key ID
      Password: API Key Secret
    Header:
      Authorization: Basic base64("{API Key ID}:{API Key Secret}")

Environment Variables (GlobalEnv mode):
    ENV0_API_URL             (optional, default: https://api.env0.com)
    ENV0_ORGANIZATION_ID     (required)
    ENV0_API_KEY             (required)
    ENV0_API_SECRET          (required)

Kubernetes Secret (UseKubeSecret / BuildKubeSecret):
    Type: Opaque
    Keys (Option A):
      ENV0_API_KEY
      ENV0_API_SECRET
      ENV0_ORGANIZATION_ID
      ENV0_API_URL

Usage (library):
    from env0_connect import get_env0_config
    api_base_uri, org_oid, HEADERS = get_env0_config()

Usage (CLI examples):
    # UseKubeSecret (default) - Quiet
    python env0_connect.py -Method UseKubeSecret -Launch Quiet -Namespace my-namespace

    # BuildKubeSecret (creates secret if missing)
    python env0_connect.py -Method BuildKubeSecret -Launch Quiet -Namespace my-namespace -SecretName EnvZero-Connect-Secret \
      -apiKey "xxx" -apiSecret "yyy" -ENV0_ORG_ID "org-xxxx" -ENV0_API_URI "https://api.env0.com"

    # Menu mode (loops until valid creds, then select org)
    python env0_connect.py -Launch Menu

    # Sandbox mode (validate + smoke tests + optional REPL)
    python env0_connect.py -Launch Sandbox
"""

import sys
import urllib3
import os
import base64 as b64
import json
import time
import logging
import argparse
import subprocess
import getpass
from typing import Optional, Tuple, Dict, Any

import requests


# ---------------------------- logging ----------------------------

_LOGGER = logging.getLogger("env0_connect")


def _configure_logging():
    if _LOGGER.handlers:
        return

    _LOGGER.setLevel(logging.DEBUG)
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(logging.DEBUG)
    formatter = logging.Formatter(
        fmt="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    handler.setFormatter(formatter)
    _LOGGER.addHandler(handler)


def _mask(value: Optional[str], keep: int = 3) -> str:
    if not value:
        return "<empty>"
    if len(value) <= keep * 2:
        return "*" * len(value)
    return f"{value[:keep]}***{value[-keep:]}"


# ---------------------------- env0 helpers ----------------------------

def _build_headers(api_key: str, api_secret: str) -> Dict[str, str]:
    token = b64.b64encode(f"{api_key}:{api_secret}".encode("utf-8")).decode("ascii")
    return {
        "Authorization": f"Basic {token}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }


def _env0_list_organizations(api_base_uri: str, headers: Dict[str, str], timeout: int = 30, verify_tls: bool = True) -> Any:
    url = f"{api_base_uri.rstrip('/')}/organizations"
    _LOGGER.debug(f"Validating env0 credentials using GET {url}")
    resp = requests.get(url, headers=headers, timeout=timeout, verify=verify_tls)
    if resp.status_code == 401:
        _LOGGER.debug("env0 auth validation returned 401 (Unauthorized).")
        raise PermissionError("Unauthorized (401). Invalid API Key ID / API Key Secret.")
    resp.raise_for_status()
    return resp.json()


def _extract_org_candidates(orgs_json: Any) -> list:
    """
    Best-effort extraction of org candidates from env0 /organizations response.
    Returns list of dicts: [{"id": "...", "name": "..."}]
    """
    candidates = []

    if isinstance(orgs_json, list):
        items = orgs_json
    elif isinstance(orgs_json, dict):
        # Some APIs wrap results; handle common shapes.
        items = (
            orgs_json.get("documents")
            or orgs_json.get("items")
            or orgs_json.get("data")
            or orgs_json.get("organizations")
            or []
        )
    else:
        items = []

    for item in items:
        if not isinstance(item, dict):
            continue
        oid = item.get("id") or item.get("organizationId") or item.get("oid") or item.get("_id")
        name = item.get("name") or item.get("organizationName") or item.get("title") or ""
        if oid:
            candidates.append({"id": oid, "name": name})

    return candidates


# ---------------------------- Kubernetes helpers ----------------------------

def _kubectl_get_secret_json(secret_name: str, namespace: str) -> Optional[Dict[str, Any]]:
    cmd = ["kubectl", "get", "secret", secret_name, "-n", namespace, "-o", "json"]
    _LOGGER.debug(f"kubectl read secret: {' '.join(cmd)}")
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        _LOGGER.debug(f"kubectl get secret failed (rc={proc.returncode}). stderr={proc.stderr.strip()}")
        return None
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError:
        _LOGGER.error("Failed to parse kubectl secret JSON output.")
        return None


def _kubectl_apply_secret_manifest(secret_manifest: Dict[str, Any]) -> None:
    cmd = ["kubectl", "apply", "-f", "-"]
    payload = json.dumps(secret_manifest).encode("utf-8")
    _LOGGER.debug(f"kubectl apply secret manifest via stdin: {' '.join(cmd)}")
    proc = subprocess.run(cmd, input=payload, capture_output=True)
    if proc.returncode != 0:
        stderr = proc.stderr.decode("utf-8", errors="ignore").strip()
        raise RuntimeError(f"kubectl apply failed (rc={proc.returncode}): {stderr}")
    _LOGGER.debug(proc.stdout.decode("utf-8", errors="ignore").strip())


def _decode_k8s_data_field(data_field: Dict[str, str]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for k, v in (data_field or {}).items():
        try:
            out[k] = b64.b64decode(v.encode("utf-8")).decode("utf-8")
        except Exception:
            out[k] = ""
    return out


def _kube_python_load():
    try:
        from kubernetes import client, config  # type: ignore
        from kubernetes.client.rest import ApiException  # type: ignore
        return client, config, ApiException
    except Exception as e:
        raise ImportError(
            "Kubernetes python client not available. Install with: pip install kubernetes"
        ) from e


def _kube_python_get_secret(secret_name: str, namespace: str) -> Optional[Dict[str, Any]]:
    client, config, ApiException = _kube_python_load()

    # Try in-cluster first; fallback to kubeconfig
    try:
        config.load_incluster_config()
        _LOGGER.debug("Loaded in-cluster Kubernetes config.")
    except Exception:
        config.load_kube_config()
        _LOGGER.debug("Loaded local kubeconfig.")

    v1 = client.CoreV1Api()
    try:
        sec = v1.read_namespaced_secret(secret_name, namespace)
        # Convert minimal fields to dict-like
        data = sec.data or {}
        return {"data": data}
    except ApiException as ex:
        if getattr(ex, "status", None) == 404:
            return None
        raise


def _kube_python_create_secret(secret_name: str, namespace: str, string_data: Dict[str, str]) -> None:
    client, config, ApiException = _kube_python_load()

    try:
        config.load_incluster_config()
        _LOGGER.debug("Loaded in-cluster Kubernetes config.")
    except Exception:
        config.load_kube_config()
        _LOGGER.debug("Loaded local kubeconfig.")

    v1 = client.CoreV1Api()
    meta = client.V1ObjectMeta(name=secret_name, namespace=namespace)
    sec = client.V1Secret(
        api_version="v1",
        kind="Secret",
        metadata=meta,
        type="Opaque",
        string_data=string_data,
    )
    try:
        v1.create_namespaced_secret(namespace=namespace, body=sec)
    except ApiException as ex:
        # If already exists, surface as warning at higher layer
        raise


def _kube_get_secret(method_provider: str, secret_name: str, namespace: str) -> Optional[Dict[str, Any]]:
    if method_provider == "kubectl":
        return _kubectl_get_secret_json(secret_name, namespace)
    elif method_provider == "python":
        return _kube_python_get_secret(secret_name, namespace)
    else:
        raise ValueError(f"Invalid KubeProvider '{method_provider}'. Use 'kubectl' or 'python'.")


def _kube_create_secret(method_provider: str, secret_name: str, namespace: str, string_data: Dict[str, str]) -> None:
    if method_provider == "kubectl":
        manifest = {
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {
                "name": secret_name,
                "namespace": namespace,
                "labels": {
                    "app": "EnvZero-Connect-Secret"
                },
            },
            "type": "Opaque",
            "stringData": string_data,
        }
        _kubectl_apply_secret_manifest(manifest)
    elif method_provider == "python":
        _kube_python_create_secret(secret_name, namespace, string_data)
    else:
        raise ValueError(f"Invalid KubeProvider '{method_provider}'. Use 'kubectl' or 'python'.")


# ---------------------------- Launch workflows ----------------------------

_ENV0_SAAS_DEFAULT_API = "https://api.env0.com"


def _prompt_nonempty(prompt: str, secret: bool = False) -> str:
    while True:
        val = getpass.getpass(prompt) if secret else input(prompt)
        if val and val.strip():
            return val.strip()
        print("Value cannot be empty. Please try again.")


def _ascii_env0_logo() -> str:
    # Simple, dependency-free ASCII art
    return r"""
   _______ _   __ _  __
  / __/ _ \ | / /| |/_/
 / _// ___/ |/ /_>  <
/___/_/   |___//_/|_|
"""


def _menu_loop_select_org(api_base_uri: str, headers: Dict[str, str], timeout: int, verify_tls: bool) -> str:
    orgs_json = _env0_list_organizations(api_base_uri, headers, timeout=timeout, verify_tls=verify_tls)
    candidates = _extract_org_candidates(orgs_json)

    if not candidates:
        _LOGGER.warning("No organizations discovered from /organizations response. Prompting for org id.")
        return _prompt_nonempty("Enter ENV0_ORGANIZATION_ID: ")

    print("\nOrganizations:")
    for idx, org in enumerate(candidates, start=1):
        name = org.get("name") or ""
        oid = org.get("id") or ""
        print(f"  [{idx}] {oid} {('- ' + name) if name else ''}")

    while True:
        choice = _prompt_nonempty("\nSelect organization number: ")
        try:
            i = int(choice)
            if 1 <= i <= len(candidates):
                return candidates[i - 1]["id"]
        except ValueError:
            pass
        print("Invalid selection. Please enter a valid number.")


def _launch_menu(timeout: int, verify_tls: bool) -> Tuple[str, str, str]:
    print(_ascii_env0_logo())
    print("EnvZero Connect - Menu Mode\n")

    # API URL is SaaS by default; allow override via ENV0_API_URL if set.
    api_base_uri = os.environ.get("ENV0_API_URL", _ENV0_SAAS_DEFAULT_API).strip() or _ENV0_SAAS_DEFAULT_API
    _LOGGER.info(f"Using env0 API URL: {api_base_uri}")

    while True:
        api_key = _prompt_nonempty("Enter ENV0 API Key ID: ")
        api_secret = _prompt_nonempty("Enter ENV0 API Key Secret: ", secret=True)

        headers = _build_headers(api_key, api_secret)
        try:
            _env0_list_organizations(api_base_uri, headers, timeout=timeout, verify_tls=verify_tls)
            _LOGGER.info("Authentication successful.")
            org_oid = _menu_loop_select_org(api_base_uri, headers, timeout=timeout, verify_tls=verify_tls)
            return api_base_uri, org_oid, headers
        except PermissionError as e:
            _LOGGER.error(f"Authentication failed: {e}")
            print("\n❌ INVALID CREDENTIALS - PLEASE TRY AGAIN\n")
            time.sleep(3)
        except Exception as e:
            _LOGGER.error(f"Unexpected error during auth validation: {e}")
            print("\n❌ ERROR VALIDATING CREDENTIALS - PLEASE TRY AGAIN\n")
            time.sleep(3)


def _sandbox_repl(api_base_uri: str, headers: Dict[str, str], timeout: int, verify_tls: bool):
    print("\nEntering Sandbox REPL. Type 'help' for commands, 'exit' to quit.\n")
    while True:
        line = input("env0> ").strip()
        if not line:
            continue
        if line.lower() in {"exit", "quit"}:
            break
        if line.lower() == "help":
            print("Examples:")
            print("  GET /organizations")
            print("  GET /blueprints?organizationId=<org>")
            print("  POST /some/endpoint   (will prompt for JSON body)")
            print("  exit")
            continue

        parts = line.split(maxsplit=1)
        if len(parts) != 2:
            print("Invalid command. Use: METHOD /path[?query]")
            continue

        method, path = parts[0].upper(), parts[1]
        url = f"{api_base_uri.rstrip('/')}/{path.lstrip('/')}"
        body = None

        if method in {"POST", "PUT", "PATCH"}:
            raw = input("JSON body> ").strip()
            if raw:
                try:
                    body = json.loads(raw)
                except json.JSONDecodeError:
                    print("Invalid JSON. Try again.")
                    continue

        try:
            resp = requests.request(method, url, headers=headers, json=body, timeout=timeout, verify=verify_tls)
            print(f"HTTP {resp.status_code}")
            ct = resp.headers.get("Content-Type", "")
            if "application/json" in ct:
                try:
                    print(json.dumps(resp.json(), indent=2))
                except Exception:
                    print(resp.text)
            else:
                print(resp.text)
        except Exception as e:
            print(f"Request failed: {e}")


def _launch_sandbox(timeout: int, verify_tls: bool) -> Tuple[str, str, Dict[str, str]]:
    print(_ascii_env0_logo())
    print("EnvZero Connect - Sandbox Mode\n")

    api_base_uri = os.environ.get("ENV0_API_URL", _ENV0_SAAS_DEFAULT_API).strip() or _ENV0_SAAS_DEFAULT_API
    _LOGGER.info(f"Using env0 API URL: {api_base_uri}")

    api_key = _prompt_nonempty("Enter ENV0 API Key ID: ")
    api_secret = _prompt_nonempty("Enter ENV0 API Key Secret: ", secret=True)
    headers = _build_headers(api_key, api_secret)

    # Validate
    orgs_json = _env0_list_organizations(api_base_uri, headers, timeout=timeout, verify_tls=verify_tls)
    _LOGGER.info("Authentication successful.")

    # Smoke tests (Option A)
    candidates = _extract_org_candidates(orgs_json)
    if candidates:
        _LOGGER.info(f"Discovered {len(candidates)} organization(s) via /organizations.")
    else:
        _LOGGER.warning("No organizations discovered from /organizations response.")

    # Choose org
    org_oid = os.environ.get("ENV0_ORGANIZATION_ID", "").strip()
    if org_oid:
        _LOGGER.info(f"Using ENV0_ORGANIZATION_ID from environment: {org_oid}")
    else:
        org_oid = _menu_loop_select_org(api_base_uri, headers, timeout=timeout, verify_tls=verify_tls)

    # Optional REPL (Option B)
    _sandbox_repl(api_base_uri, headers, timeout=timeout, verify_tls=verify_tls)

    return api_base_uri, org_oid, headers


# ---------------------------- main exported function ----------------------------

def get_env0_config(
    method: str = "UseKubeSecret",
    launch: str = "Quiet",
    kube_provider: str = "kubectl",
    namespace: Optional[str] = None,
    secret_name: str = "EnvZero-Connect-Secret",
    apiKey: Optional[str] = None,
    apiSecret: Optional[str] = None,
    ENV0_ORG_ID: Optional[str] = None,
    ENV0_API_URI: Optional[str] = None,
    timeout: int = 30,
    verify_tls: bool = True,
) -> Tuple[str, str, Dict[str, str]]:
    """
    Return (api_base_uri, org_oid, headers) based on requested Method/Launch.

    method:
      - GlobalEnv
      - UseKubeSecret (default)
      - Base64
      - BuildKubeSecret

    launch:
      - Quiet
      - Interactive
      - Menu
      - Sandbox
    """
    _configure_logging()

    method_norm = (method or "UseKubeSecret").strip()
    launch_norm = (launch or "Quiet").strip()
    kube_provider_norm = (kube_provider or "kubectl").strip().lower()

    _LOGGER.debug(f"get_env0_config called with method={method_norm}, launch={launch_norm}, kube_provider={kube_provider_norm}, "
                  f"namespace={namespace}, secret_name={secret_name}")

    # Special launch flows that prompt/validate interactively
    if launch_norm.lower() == "menu":
        api_base_uri, org_oid, headers = _launch_menu(timeout=timeout, verify_tls=verify_tls)
        return api_base_uri, org_oid, headers

    if launch_norm.lower() == "sandbox":
        api_base_uri, org_oid, headers = _launch_sandbox(timeout=timeout, verify_tls=verify_tls)
        return api_base_uri, org_oid, headers

    # ---- Quiet / Interactive flows below ----
    launch_is_interactive = launch_norm.lower() == "interactive"
    launch_is_quiet = launch_norm.lower() == "quiet"
    if not (launch_is_quiet or launch_is_interactive):
        raise ValueError("Invalid -Launch. Use Quiet, Interactive, Menu, or Sandbox.")

    # Helper to ensure required arg presence
    def require(val: Optional[str], name: str) -> str:
        if val is None or not str(val).strip():
            raise ValueError(f"Missing required parameter: {name}")
        return str(val).strip()

    # ---------------- GlobalEnv ----------------
    if method_norm.lower() == "globalenv":
        api_base_uri = os.environ.get("ENV0_API_URL", _ENV0_SAAS_DEFAULT_API).strip() or _ENV0_SAAS_DEFAULT_API
        org_oid = os.environ.get("ENV0_ORGANIZATION_ID")
        api_key = os.environ.get("ENV0_API_KEY")
        api_secret = os.environ.get("ENV0_API_SECRET")

        _LOGGER.info(f"Auth Method=GlobalEnv. ENV0_API_URL={api_base_uri}, ENV0_ORGANIZATION_ID={org_oid}")
        _LOGGER.debug(f"GlobalEnv credentials: ENV0_API_KEY={_mask(api_key)}, ENV0_API_SECRET={_mask(api_secret)}")

        org_oid = require(org_oid, "ENV0_ORGANIZATION_ID (env var)")
        api_key = require(api_key, "ENV0_API_KEY (env var)")
        api_secret = require(api_secret, "ENV0_API_SECRET (env var)")

        headers = _build_headers(api_key, api_secret)
        return api_base_uri, org_oid, headers

    # ---------------- Base64 ----------------
    if method_norm.lower() == "base64":
        api_base_uri = require(ENV0_API_URI, "ENV0_API_URI")
        org_oid = require(ENV0_ORG_ID, "ENV0_ORG_ID")
        api_key = require(apiKey, "apiKey")
        api_secret = require(apiSecret, "apiSecret")

        _LOGGER.info("Auth Method=Base64 (internal base64(apiKey:apiSecret)).")
        _LOGGER.debug(f"Base64 inputs: apiKey={_mask(api_key)}, apiSecret={_mask(api_secret)}, ENV0_ORG_ID={org_oid}, ENV0_API_URI={api_base_uri}")

        headers = _build_headers(api_key, api_secret)
        return api_base_uri, org_oid, headers

    # ---------------- UseKubeSecret / BuildKubeSecret ----------------
    if method_norm.lower() not in {"usekubesecret", "buildkubesecret"}:
        raise ValueError("Invalid -Method. Use GlobalEnv, UseKubeSecret, Base64, or BuildKubeSecret.")

    namespace_val = namespace or os.environ.get("ENV0_KUBE_NAMESPACE")
    if not namespace_val:
        raise ValueError("Missing required parameter: Namespace (or set ENV0_KUBE_NAMESPACE).")
    namespace_val = namespace_val.strip()

    secret_name_val = (secret_name or "EnvZero-Connect-Secret").strip() or "EnvZero-Connect-Secret"

    _LOGGER.info(f"Auth Method={method_norm}. KubeProvider={kube_provider_norm}. Namespace={namespace_val}. SecretName={secret_name_val}")

    existing = _kube_get_secret(kube_provider_norm, secret_name_val, namespace_val)

    if method_norm.lower() == "usekubesecret":
        if not existing:
            msg = (
                f"Kubernetes Secret '{secret_name_val}' not found in namespace '{namespace_val}'. "
                f"Run: env0_connect.py -Method BuildKubeSecret -Namespace {namespace_val} -SecretName {secret_name_val} "
                f"-apiKey <...> -apiSecret <...> -ENV0_ORG_ID <...> -ENV0_API_URI {_ENV0_SAAS_DEFAULT_API}"
            )
            if launch_is_quiet:
                _LOGGER.error(msg)
                raise FileNotFoundError(msg)

            # Interactive: prompt user for required fields and create it
            _LOGGER.warning(msg)
            print("\nSecret not found. Interactive mode will build the secret now.\n")
            api_key = _prompt_nonempty("Enter ENV0 API Key ID: ")
            api_secret = _prompt_nonempty("Enter ENV0 API Key Secret: ", secret=True)
            org_oid = _prompt_nonempty("Enter ENV0_ORGANIZATION_ID: ")
            api_base_uri = os.environ.get("ENV0_API_URL", _ENV0_SAAS_DEFAULT_API).strip() or _ENV0_SAAS_DEFAULT_API

            string_data = {
                "ENV0_API_KEY": api_key,
                "ENV0_API_SECRET": api_secret,
                "ENV0_ORGANIZATION_ID": org_oid,
                "ENV0_API_URL": api_base_uri,
            }
            _LOGGER.info(f"Creating Kubernetes Secret '{secret_name_val}' (Opaque) in namespace '{namespace_val}' via {kube_provider_norm}.")
            _kube_create_secret(kube_provider_norm, secret_name_val, namespace_val, string_data)

            existing = _kube_get_secret(kube_provider_norm, secret_name_val, namespace_val)
            if not existing:
                raise RuntimeError("Secret creation attempted but secret still not readable. Check RBAC / namespace / provider.")

        # Read from secret
        data_field = existing.get("data") or {}
        decoded = _decode_k8s_data_field(data_field)

        api_base_uri = decoded.get("ENV0_API_URL", "").strip() or _ENV0_SAAS_DEFAULT_API
        org_oid = decoded.get("ENV0_ORGANIZATION_ID", "").strip()
        api_key = decoded.get("ENV0_API_KEY", "").strip()
        api_secret = decoded.get("ENV0_API_SECRET", "").strip()

        _LOGGER.debug(f"Secret read results: ENV0_API_URL={api_base_uri}, ENV0_ORGANIZATION_ID={org_oid}, "
                      f"ENV0_API_KEY={_mask(api_key)}, ENV0_API_SECRET={_mask(api_secret)}")

        org_oid = require(org_oid, "ENV0_ORGANIZATION_ID (from secret)")
        api_key = require(api_key, "ENV0_API_KEY (from secret)")
        api_secret = require(api_secret, "ENV0_API_SECRET (from secret)")

        headers = _build_headers(api_key, api_secret)
        return api_base_uri, org_oid, headers

    # ---------------- BuildKubeSecret ----------------
    # Required flags are mandatory
    api_base_uri = require(ENV0_API_URI, "ENV0_API_URI")
    org_oid = require(ENV0_ORG_ID, "ENV0_ORG_ID")
    api_key = require(apiKey, "apiKey")
    api_secret = require(apiSecret, "apiSecret")

    if existing:
        _LOGGER.warning(f"Kubernetes Secret '{secret_name_val}' already exists in namespace '{namespace_val}'. Using existing secret (no overwrite).")
        # Use existing secret values
        data_field = existing.get("data") or {}
        decoded = _decode_k8s_data_field(data_field)

        api_base_uri = decoded.get("ENV0_API_URL", "").strip() or api_base_uri
        org_oid = decoded.get("ENV0_ORGANIZATION_ID", "").strip() or org_oid
        api_key = decoded.get("ENV0_API_KEY", "").strip() or api_key
        api_secret = decoded.get("ENV0_API_SECRET", "").strip() or api_secret
    else:
        _LOGGER.info(f"Creating Kubernetes Secret '{secret_name_val}' (Opaque) in namespace '{namespace_val}' via {kube_provider_norm}.")
        string_data = {
            "ENV0_API_KEY": api_key,
            "ENV0_API_SECRET": api_secret,
            "ENV0_ORGANIZATION_ID": org_oid,
            "ENV0_API_URL": api_base_uri,
        }
        _kube_create_secret(kube_provider_norm, secret_name_val, namespace_val, string_data)

    headers = _build_headers(api_key, api_secret)
    return api_base_uri, org_oid, headers


# ---------------------------- CLI entrypoint ----------------------------

def _build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="env0_connect.py - env0 API auth wrapper")

    # Keep user-requested flag shapes (-Method etc.)
    p.add_argument("-Method", "--Method", dest="Method", default="UseKubeSecret",
                   choices=["GlobalEnv", "UseKubeSecret", "Base64", "BuildKubeSecret"],
                   help="Authentication method (default: UseKubeSecret).")

    p.add_argument("-Launch", "--Launch", dest="Launch", default="Quiet",
                   choices=["Quiet", "Interactive", "Menu", "Sandbox"],
                   help="Launch mode (default: Quiet).")

    p.add_argument("-KubeProvider", "--KubeProvider", dest="KubeProvider", default="kubectl",
                   choices=["kubectl", "python"],
                   help="Kubernetes provider (default: kubectl).")

    p.add_argument("-Namespace", "--Namespace", dest="Namespace", default=None,
                   help="Kubernetes namespace (required for UseKubeSecret/BuildKubeSecret).")

    p.add_argument("-SecretName", "--SecretName", dest="SecretName", default="EnvZero-Connect-Secret",
                   help="Kubernetes secret name (default: EnvZero-Connect-Secret).")

    # Mandatory for Base64/BuildKubeSecret
    p.add_argument("-apiKey", "--apiKey", dest="apiKey", default=None, help="env0 API Key ID.")
    p.add_argument("-apiSecret", "--apiSecret", dest="apiSecret", default=None, help="env0 API Key Secret.")
    p.add_argument("-ENV0_ORG_ID", "--ENV0_ORG_ID", dest="ENV0_ORG_ID", default=None, help="env0 Organization ID.")
    p.add_argument("-ENV0_API_URI", "--ENV0_API_URI", dest="ENV0_API_URI", default=None, help="env0 API URL.")

    p.add_argument("-NoTLSVerify", "--NoTLSVerify", dest="NoTLSVerify", action="store_true",
                   help="Disable TLS verification (not recommended).")

    return p


if __name__ == "__main__":
    _configure_logging()

    parser = _build_arg_parser()
    args = parser.parse_args()

    verify_tls = not bool(args.NoTLSVerify)
    if not verify_tls:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        _LOGGER.warning("TLS verification is disabled (-NoTLSVerify).")

    api_base_uri, org_oid, headers = get_env0_config(
        method=args.Method,
        launch=args.Launch,
        kube_provider=args.KubeProvider,
        namespace=args.Namespace,
        secret_name=args.SecretName,
        apiKey=args.apiKey,
        apiSecret=args.apiSecret,
        ENV0_ORG_ID=args.ENV0_ORG_ID,
        ENV0_API_URI=args.ENV0_API_URI,
        verify_tls=verify_tls,
    )

    # Summary (do not print secrets)
    _LOGGER.info(f"env0_connect ready. api_base_uri={api_base_uri}, org_oid={org_oid}, Authorization=Basic {_mask(headers.get('Authorization', ''))}")
