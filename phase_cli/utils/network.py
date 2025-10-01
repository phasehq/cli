import os
import requests
from phase_cli.utils.misc import get_user_agent, build_public_api_url
from phase_cli.exceptions import AuthorizationError, APIError, SSLError
from typing import List
from typing import Dict
from typing import Optional
import json

# Check if SSL verification should be skipped
VERIFY_SSL = os.environ.get('PHASE_VERIFY_SSL', 'True').lower() != 'false'

# Check if debug mode is enabled
PHASE_DEBUG = os.environ.get('PHASE_DEBUG', 'False').lower() == 'true'

# Suppress InsecureRequestWarning if SSL verification is skipped
if not VERIFY_SSL:
    requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)


def handle_response_errors(response: requests.Response) -> None:
    """
    Handle JSON decode errors from API responses.
    
    Args:
        response (requests.Response): The HTTP response that failed to decode.
    
    Raises:
        APIError: An error with details about the invalid response.
    """
    error_message = "🗿 Unexpected response received from the Phase API. Please set PHASE_DEBUG=True to see the error & response."
    
    if PHASE_DEBUG and response.text:
        # Print the first 500 characters of the response if PHASE_DEBUG is enabled
        truncated_text = response.text[:500]
        if len(response.text) > 500:
            truncated_text += "... [truncated]"
        error_message += f"\nResponse preview: {truncated_text}"
    
    raise APIError(error_message)


def handle_request_errors(response: requests.Response) -> None:
    """
    Check the HTTP status code of a response and print the error if the status code is not 200.
    
    Args:
        response (requests.Response): The HTTP response to check.
    """
    # Handle access control / token revocation expiry related errors
    if response.status_code == 403:
        try:
            # Check if the API response contains an error
            error_data = response.json()
            if 'error' in error_data:
                raise AuthorizationError(f"🚫 Not authorized. {error_data['error']}")
            else:
                raise AuthorizationError("🚫 Not authorized.")
        except json.JSONDecodeError:
            raise AuthorizationError("🚫 Not authorized.")
    
    # Handle generic API errors
    if response.status_code != 200:
        try:
            error_details = json.loads(response.text).get('error', 'Unknown error')
        except json.JSONDecodeError:
            error_details = 'Unknown error'
            if PHASE_DEBUG:
                error_details += f" (Raw response: {response.text})"
        
        error_message = f"🗿 Request failed with status code {response.status_code}: {error_details}"
        raise APIError(error_message)


def handle_connection_error(e: Exception) -> None:
    """
    Handle ConnectionError exceptions.

    Args:
        e (Exception): The exception to handle.
    """
    error_message = "🗿 Network error: Please check your connection."
    if PHASE_DEBUG:
        error_message += f" Detail: {str(e)}"
    raise ConnectionError(error_message)


def handle_ssl_error(e: Exception) -> None:
    """
    Handle SSLError exceptions.

    Args:
        e (Exception): The exception to handle.
    """
    error_message = "🗿 SSL error: The Phase Console is using an invalid/expired or a self-signed certificate. You may ignore this error by setting PHASE_VERIFY_SSL=False"
    if PHASE_DEBUG:
        error_message += f" Detail: {str(e)}"
    raise SSLError(error_message)


def construct_http_headers(token_type: str, app_token: str) -> Dict[str, str]:
    """
    Construct common headers used for HTTP requests.
    
    Args:
        token_type (str): The type of token being used.
        app_token (str): The token for the application.
    
    Returns:
        Dict[str, str]: The common headers including User-Agent.
    """
    return {
        "Authorization": f"Bearer {token_type} {app_token}",
        "User-Agent": get_user_agent()
    }


def fetch_phase_user(token_type: str, app_token: str, host: str) -> requests.Response:
    """
    Fetch users from the Phase API.

    Args:
        app_token (str): The token for the application.

    Returns:
        requests.Response: The HTTP response from the Phase KMS.
    """

    headers = construct_http_headers(token_type, app_token)

    URL =  f"{host}/service/secrets/tokens/"

    try:
        response = requests.get(URL, headers=headers, verify=VERIFY_SSL)
        handle_request_errors(response)
        # Only try to parse JSON if response has content
        if response.text.strip():
            try:
                response.json()
            except json.JSONDecodeError:
                handle_response_errors(response)
        return response
    except requests.exceptions.SSLError as e:
        handle_ssl_error(e)
    except requests.exceptions.ConnectionError as e:
        handle_connection_error(e)

def fetch_app_key(token_type: str, app_token, host) -> str:
    """
    Fetches the application key share from Phase KMS.

    Args:
        app_token (str): The token for the application to retrieve the key for.
        token_type (str): The type of token being used, either "user" or "service". Defaults to "user".

    Returns:
        str: The wrapped key share.
    Raises:
        Exception: If the app token is invalid (HTTP status code 404).
    """

    headers = construct_http_headers(token_type, app_token)

    URL =  f"{host}/service/secrets/tokens/"

    response = requests.get(URL, headers=headers, verify=VERIFY_SSL)

    if response.status_code != 200:
        raise ValueError(f"Request failed with status code {response.status_code}: {response.text}")

    if not response.text:
        raise ValueError("The response body is empty!")

    try:
        json_data = response.json()
    except json.JSONDecodeError:
        handle_response_errors(response)

    wrapped_key_share = json_data.get("wrapped_key_share")
    if not wrapped_key_share:
        raise ValueError("Wrapped key share not found in the response!")

    return wrapped_key_share


def fetch_wrapped_key_share(token_type: str, app_token: str, host: str) -> str:
    """
    Fetches the wrapped application key share from Phase KMS.

    Args:
        token_type (str): The type of token being used, either "user" or "service".
        app_token (str): The token for the application to retrieve the key for.
        host (str): The host for the API call.

    Returns:
        str: The wrapped key share.

    Raises:
        ValueError: If any errors occur during the fetch operation.
    """

    headers = construct_http_headers(token_type, app_token)

    URL = f"{host}/service/secrets/tokens/"

    response = requests.get(URL, headers=headers, verify=VERIFY_SSL)

    if response.status_code != 200:
        raise ValueError(f"Request failed with status code {response.status_code}: {response.text}")

    if not response.text:
        raise ValueError("The response body is empty!")

    try:
        json_data = response.json()
    except json.JSONDecodeError:
        handle_response_errors(response)

    wrapped_key_share = json_data.get("wrapped_key_share")
    if not wrapped_key_share:
        raise ValueError("Wrapped key share not found in the response!")

    return wrapped_key_share

# Static secrets

def fetch_phase_secrets(token_type: str, app_token: str, id: str, host: str, key_digest: str = '', path: str = '', dynamic: bool = False, lease: bool = False, lease_ttl: Optional[int] = None) -> requests.Response:
    """
    Fetch a single secret from Phase KMS based on key digest, with an optional path parameter.

    Args:
        token_type (str): The type of the token.
        app_token (str): The token for the application.
        id (str): The environment ID.
        host (str): The host URL.
        key_digest (str): The digest of the key to fetch.
        path (str, optional): A specific path to fetch secrets from.

    Returns:
        dict: The single secret fetched from the Phase KMS, or an error message.
    """

    headers = {**construct_http_headers(token_type, app_token), "Environment": id, "KeyDigest": key_digest}
    if path:
        headers["Path"] = path
    if dynamic:
        headers["dynamic"] = "true"
    if lease:
        headers["lease"] = "true"
    if lease_ttl is not None:
        headers["lease-ttl"] = str(lease_ttl)

    URL = f"{host}/service/secrets/"

    try:
        response = requests.get(URL, headers=headers, verify=VERIFY_SSL)
        handle_request_errors(response)
        # Only try to parse JSON if response has content
        if response.text.strip():
            try:
                response.json()
            except json.JSONDecodeError:
                handle_response_errors(response)
        return response
    except requests.exceptions.SSLError as e:
        handle_ssl_error(e)
    except requests.exceptions.ConnectionError as e:
        handle_connection_error(e)

def create_phase_secrets(token_type: str, app_token: str, environment_id: str, secrets: List[dict], host: str) -> requests.Response:
    """
    Create secrets in Phase KMS through HTTP POST request.

    Args:
        app_token (str): The token for the application.
        environment_id (str): The environment ID.
        secrets (List[dict]): The list of secrets to be created.

    Returns:
        requests.Response: The HTTP response from the Phase KMS.
    """

    headers = {**construct_http_headers(token_type, app_token), "Environment": environment_id}

    data = {
        "secrets": secrets
    }

    URL =  f"{host}/service/secrets/"

    try:
        response = requests.post(URL, headers=headers, json=data, verify=VERIFY_SSL)
        handle_request_errors(response)
        # Only try to parse JSON if response has content
        if response.text.strip():
            try:
                response.json()
            except json.JSONDecodeError:
                handle_response_errors(response)
        return response
    except requests.exceptions.SSLError as e:
        handle_ssl_error(e)
    except requests.exceptions.ConnectionError as e:
        handle_connection_error(e)


def update_phase_secrets(token_type: str, app_token: str, environment_id: str, secrets: List[dict], host: str) -> requests.Response:
    """
    Update secrets in Phase KMS through HTTP PUT request.

    Args:
        app_token (str): The token for the application.
        environment_id (str): The environment ID.
        secrets (List[dict]): The list of secrets to be updated.

    Returns:
        requests.Response: The HTTP response from the Phase KMS.
    """

    headers = {**construct_http_headers(token_type, app_token), "Environment": environment_id}

    data = {
        "secrets": secrets
    }

    URL =  f"{host}/service/secrets/"

    try:
        response = requests.put(URL, headers=headers, json=data, verify=VERIFY_SSL)
        handle_request_errors(response)
        # Only try to parse JSON if response has content
        if response.text.strip():
            try:
                response.json()
            except json.JSONDecodeError:
                handle_response_errors(response)
        return response
    except requests.exceptions.SSLError as e:
        handle_ssl_error(e)
    except requests.exceptions.ConnectionError as e:
        handle_connection_error(e)


def delete_phase_secrets(token_type: str, app_token: str, environment_id: str, secret_ids: List[str], host: str) -> requests.Response:
    """
    Delete secrets from Phase KMS.

    Args:
        app_token (str): The token for the application.
        environment_id (str): The environment ID.
        secret_ids (List[str]): The list of secret IDs to be deleted.

    Returns:
        requests.Response: The HTTP response from the Phase KMS.
    """

    headers = {**construct_http_headers(token_type, app_token), "Environment": environment_id}

    data = {
        "secrets": secret_ids
    }

    URL =  f"{host}/service/secrets/"

    try:
        response = requests.delete(URL, headers=headers, json=data, verify=VERIFY_SSL)
        handle_request_errors(response)
        # Only try to parse JSON if response has content
        if response.text.strip():
            try:
                response.json()
            except json.JSONDecodeError:
                handle_response_errors(response)
        return response
    except requests.exceptions.SSLError as e:
        handle_ssl_error(e)
    except requests.exceptions.ConnectionError as e:
        handle_connection_error(e)

# Dynamic secrets

def create_dynamic_secret_lease(token_type: str, app_token: str, host: str, app_id: str, env: str, secret_id: str, ttl: Optional[int] = None) -> requests.Response:
    """
    Generate a dynamic secret lease by calling GET /v1/secrets/dynamic/ with lease=true.

    Query params:
        app_id (str)
        env (str)
        id (str)            # dynamic secret id
        lease (bool=true)
    """

    headers = construct_http_headers(token_type, app_token)

    url = build_public_api_url(host, "/v1/secrets/dynamic/")

    params: Dict[str, str] = {"app_id": app_id, "env": env, "lease": "true", "id": secret_id}
    if ttl is not None:
        params["ttl"] = str(ttl)

    try:
        response = requests.get(url, headers=headers, params=params, verify=VERIFY_SSL)
        handle_request_errors(response)
        if response.text.strip():
            try:
                response.json()
            except json.JSONDecodeError:
                handle_response_errors(response)
        return response
    except requests.exceptions.SSLError as e:
        handle_ssl_error(e)
    except requests.exceptions.ConnectionError as e:
        handle_connection_error(e)


def list_dynamic_secret_leases(token_type: str, app_token: str, host: str, app_id: str, env: str, secret_id: Optional[str] = None) -> requests.Response:
    """
    List dynamic secret leases.

    Query params:
        app_id (str): Application ID
        env (str): Environment name
        secret_id (Optional[str]): Secret ID to filter leases
    """

    headers = construct_http_headers(token_type, app_token)

    url = build_public_api_url(host, "/v1/secrets/dynamic/leases/")

    params = {"app_id": app_id, "env": env}
    if secret_id:
        params["secret_id"] = secret_id

    try:
        response = requests.get(url, headers=headers, params=params, verify=VERIFY_SSL)
        handle_request_errors(response)
        if response.text.strip():
            try:
                response.json()
            except json.JSONDecodeError:
                handle_response_errors(response)
        return response
    except requests.exceptions.SSLError as e:
        handle_ssl_error(e)
    except requests.exceptions.ConnectionError as e:
        handle_connection_error(e)


def renew_dynamic_secret_lease(token_type: str, app_token: str, host: str, app_id: str, env: str, lease_id: str, ttl: int) -> requests.Response:
    """
    Renew a dynamic secret lease.

    Query params:
        app_id (str)
        env (str)

    Body:
        lease_id (str)
        ttl (int)
    """

    headers = construct_http_headers(token_type, app_token)

    url = build_public_api_url(host, "/v1/secrets/dynamic/leases/")

    params = {"app_id": app_id, "env": env}
    data = {"lease_id": lease_id, "ttl": ttl}

    try:
        response = requests.put(url, headers=headers, params=params, json=data, verify=VERIFY_SSL)
        handle_request_errors(response)
        if response.text.strip():
            try:
                response.json()
            except json.JSONDecodeError:
                handle_response_errors(response)
        return response
    except requests.exceptions.SSLError as e:
        handle_ssl_error(e)
    except requests.exceptions.ConnectionError as e:
        handle_connection_error(e)


def revoke_dynamic_secret_lease(token_type: str, app_token: str, host: str, app_id: str, env: str, lease_id: str) -> requests.Response:
    """
    Revoke a dynamic secret lease.

    Query params:
        app_id (str)
        env (str)

    Body:
        lease_id (str)
    """

    headers = construct_http_headers(token_type, app_token)

    url = build_public_api_url(host, "/v1/secrets/dynamic/leases/")

    params = {"app_id": app_id, "env": env}
    data = {"lease_id": lease_id}

    try:
        response = requests.delete(url, headers=headers, params=params, json=data, verify=VERIFY_SSL)
        handle_request_errors(response)
        if response.text.strip():
            try:
                response.json()
            except json.JSONDecodeError:
                handle_response_errors(response)
        return response
    except requests.exceptions.SSLError as e:
        handle_ssl_error(e)
    except requests.exceptions.ConnectionError as e:
        handle_connection_error(e)


def list_dynamic_secrets(token_type: str, app_token: str, host: str, app_id: str, env: str, path: Optional[str] = None) -> requests.Response:
    """
    List dynamic secrets metadata via public API.

    Query params:
        app_id (str)
        env (str)
        path (Optional[str])
    """

    headers = construct_http_headers(token_type, app_token)

    url = build_public_api_url(host, "/v1/secrets/dynamic/")

    params: Dict[str, str] = {"app_id": app_id, "env": env}
    if path is not None:
        params["path"] = path

    try:
        response = requests.get(url, headers=headers, params=params, verify=VERIFY_SSL)
        handle_request_errors(response)
        if response.text.strip():
            try:
                response.json()
            except json.JSONDecodeError:
                handle_response_errors(response)
        return response
    except requests.exceptions.SSLError as e:
        handle_ssl_error(e)
    except requests.exceptions.ConnectionError as e:
        handle_connection_error(e)
