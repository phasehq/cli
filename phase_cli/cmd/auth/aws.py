from botocore.awsrequest import AWSRequest
from botocore.auth import SigV4Auth
from botocore.credentials import get_credentials
from botocore.session import get_session
from botocore.config import Config
from phase_cli.utils.network import external_identity_auth_aws
from phase_cli.utils.const import AWS_DEFAULT_GLOBAL_STS_REGION, AWS_DEFAULT_GLOBAL_STS_ENDPOINT


def resolve_region_and_endpoint() -> tuple[str, str]:
    session = get_session()
    aws_region = session.get_config_variable('region')
    if not aws_region:
        try:
            client_config = Config(region_name=None)
            session.create_client('sts', config=client_config)
            aws_region = session.get_config_variable('region')
        except Exception:
            pass

    if aws_region:
        return aws_region, f"https://sts.{aws_region}.amazonaws.com"

    # Fallback to legacy global endpoint, sign with us-east-1
    return AWS_DEFAULT_GLOBAL_STS_REGION, AWS_DEFAULT_GLOBAL_STS_ENDPOINT


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


def perform_aws_iam_auth(host: str, service_account_id: str, ttl: int | None = None, method: str = "POST"):
    """
    Perform complete AWS IAM authentication flow with Phase.
    
    Args:
        host: Phase API base URL
        service_account_id: Service Account ID to authenticate (UUID)
        ttl: Requested token TTL in seconds (optional)
        method: HTTP method to sign (default: POST)
    
    Returns:
        dict: Authentication response from Phase API containing token
    """
    region, endpoint = resolve_region_and_endpoint()
    signed = sign_get_caller_identity(region=region, endpoint=endpoint, method=method)
    result = external_identity_auth_aws(host, service_account_id, ttl, signed, method=method)
    return result
