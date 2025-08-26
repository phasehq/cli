#!/usr/bin/env python3
import base64
import json
import os
import sys
from urllib.parse import urljoin

import requests
from botocore.awsrequest import AWSRequest
from botocore.auth import SigV4Auth
from botocore.credentials import get_credentials
from botocore.session import get_session

DEFAULT_PATH = "/service/identity/v1/aws/iam/auth"
DEFAULT_GLOBAL_STS = "https://sts.amazonaws.com"
DEFAULT_REGION_FOR_GLOBAL_STS = "us-east-1"


def b64_str(s: str) -> str:
    return base64.b64encode(s.encode("utf-8")).decode("utf-8")


def resolve_region_and_endpoint(cli_region: str | None, cli_sts_endpoint: str | None) -> tuple[str, str]:
    session = get_session()
    detected_region = cli_region or session.get_config_variable('region') or os.environ.get('AWS_DEFAULT_REGION')
    
    if cli_sts_endpoint:
        endpoint = cli_sts_endpoint if cli_sts_endpoint.startswith("http") else f"https://{cli_sts_endpoint}"
        region = detected_region or DEFAULT_REGION_FOR_GLOBAL_STS
        return region, endpoint

    if detected_region:
        # Prefer regional STS endpoint when region is known
        return detected_region, f"https://sts.{detected_region}.amazonaws.com"

    # Fallback to legacy global endpoint, sign with us-east-1
    return DEFAULT_REGION_FOR_GLOBAL_STS, DEFAULT_GLOBAL_STS


def sign_get_caller_identity(region: str, endpoint: str, method: str = "POST") -> tuple[str, dict, str]:
    """
    Returns (signed_url, signed_headers, body) for GetCallerIdentity.
    Uses header-based SigV4 (includes X-Amz-Date header).
    """
    # STS Query API (Action=GetCallerIdentity&Version=2011-06-15)
    body = "Action=GetCallerIdentity&Version=2011-06-15"
    headers = {"Content-Type": "application/x-www-form-urlencoded; charset=utf-8"}

    session = get_session()
    creds = session.get_credentials()
    if creds is None:
        raise SystemExit("No AWS credentials found. On EC2, attach an instance profile or set AWS_* env vars.")

    frozen = creds.get_frozen_credentials()
    req = AWSRequest(method=method, url=endpoint, data=body, headers=headers)
    SigV4Auth(frozen, "sts", region).add_auth(req)
    prepared = req.prepare()

    signed_url = prepared.url
    signed_headers = dict(prepared.headers.items())
    return signed_url, signed_headers, body


def authenticate_with_phase(phase_base: str, service_account_id: str, ttl: int | None, signed_request: tuple[str, dict, str], method: str = "POST"):
    """
    Authenticate with Phase using AWS IAM credentials.
    
    Args:
        phase_base: Phase API base URL
        service_account_id: Service Account ID to authenticate (UUID)
        ttl: Requested token TTL in seconds (optional)
        signed_request: Tuple of (signed_url, signed_headers, body) from sign_get_caller_identity
        method: HTTP method used for signing (default: POST)
    
    Returns:
        dict: Authentication response from Phase API
    """
    signed_url, signed_headers, body = signed_request
    payload = {
        "account": {
            "type": "service",
            "id": service_account_id,
        },
        "awsIam": {
            "httpRequestMethod": method,
            "httpRequestUrl": b64_str(signed_url),
            "httpRequestHeaders": b64_str(json.dumps(signed_headers)),
            "httpRequestBody": b64_str(body),
        },
    }
    if ttl is not None:
        payload["tokenRequest"] = {"ttl": int(ttl)}

    url = urljoin(phase_base.rstrip("/") + "/", DEFAULT_PATH.lstrip("/"))
    resp = requests.post(url, json=payload, timeout=20)
    if resp.status_code != 200:
        raise Exception(f"Phase auth failed ({resp.status_code}): {resp.text}")

    return resp.json()


def perform_aws_iam_auth(phase_base: str, service_account_id: str, ttl: int | None = None, region: str | None = None, sts_endpoint: str | None = None, method: str = "POST"):
    """
    Perform complete AWS IAM authentication flow with Phase.
    
    Args:
        phase_base: Phase API base URL
        service_account_id: Service Account ID to authenticate (UUID)
        ttl: Requested token TTL in seconds (optional)
        region: AWS region to sign with (optional)
        sts_endpoint: Custom STS endpoint (optional)
        method: HTTP method to sign (default: POST)
    
    Returns:
        dict: Authentication response from Phase API containing token
    """
    region, endpoint = resolve_region_and_endpoint(region, sts_endpoint)
    signed = sign_get_caller_identity(region=region, endpoint=endpoint, method=method)
    result = authenticate_with_phase(phase_base, service_account_id, ttl, signed, method=method)
    return result
