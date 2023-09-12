import os
import requests
from typing import List

# Check if SSL verification should be skipped
VERIFY_SSL = os.environ.get('PHASE_VERIFY_SSL', 'True').lower() != 'false'

# Check if debug mode is enabled
PHASE_DEBUG = os.environ.get('PHASE_DEBUG', 'False').lower() == 'true'

# Suppress InsecureRequestWarning if SSL verification is skipped
if not VERIFY_SSL:
    requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)


def handle_request_errors(response: requests.Response) -> None:
    """
    Check the HTTP status code of a response and raise an exception with
    an informative message if the status code is not 200.

    Args:
        response (requests.Response): The HTTP response to check.
    """
    if response.status_code == 403:
        print("🚫 Not authorized. Token expired or revoked.")
        return
    
    if response.status_code != 200:
        error_message = f"🗿 Request failed with status code {response.status_code}"
        if PHASE_DEBUG:
            error_message += f": {response.text}"
        raise Exception(error_message)


def handle_connection_error(e: Exception) -> None:
    """
    Handle ConnectionError exceptions.

    Args:
        e (Exception): The exception to handle.
    """
    error_message = "🗿 Network error: Please check your internet connection."
    if PHASE_DEBUG:
        error_message += f" Detail: {str(e)}"
    raise Exception(error_message)


def handle_ssl_error(e: Exception) -> None:
    """
    Handle SSLError exceptions.

    Args:
        e (Exception): The exception to handle.
    """
    error_message = "🗿 SSL error: The Phase Console is using an invalid/expired or a self-signed certificate."
    if PHASE_DEBUG:
        error_message += f" Detail: {str(e)}"
    raise Exception(error_message)


def fetch_phase_user(token_type: str, app_token: str, host: str) -> requests.Response:
    """
    Fetch users from the Phase API.

    Args:
        app_token (str): The token for the application.

    Returns:
        requests.Response: The HTTP response from the Phase KMS.
    """

    headers = {
        "Authorization": f"Bearer {token_type.capitalize()} {app_token}",
    }

    URL =  f"{host}/secrets/tokens/"

    try:
        response = requests.get(URL, headers=headers, verify=VERIFY_SSL)
        handle_request_errors(response)
        return response
    except requests.exceptions.ConnectionError as e:
        handle_connection_error(e)
    except requests.exceptions.SSLError as e:
        handle_ssl_error(e)

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

    headers = {
        "Authorization": f"Bearer {token_type.capitalize()} {app_token}",
    }

    URL =  f"{host}/secrets/tokens/"

    response = requests.get(URL, headers=headers)

    if response.status_code != 200:
        raise ValueError(f"Request failed with status code {response.status_code}: {response.text}")

    if not response.text:
        raise ValueError("The response body is empty!")

    try:
        json_data = response.json()
    except requests.exceptions.JSONDecodeError:
        raise ValueError(f"Failed to decode JSON from response: {response.text}")

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

    headers = {
        "Authorization": f"Bearer {token_type.capitalize()} {app_token}",
    }

    URL = f"{host}/secrets/tokens/"

    response = requests.get(URL, headers=headers)

    if response.status_code != 200:
        raise ValueError(f"Request failed with status code {response.status_code}: {response.text}")

    if not response.text:
        raise ValueError("The response body is empty!")

    try:
        json_data = response.json()
    except requests.exceptions.JSONDecodeError:
        raise ValueError(f"Failed to decode JSON from response: {response.text}")

    wrapped_key_share = json_data.get("wrapped_key_share")
    if not wrapped_key_share:
        raise ValueError("Wrapped key share not found in the response!")

    return wrapped_key_share


def fetch_phase_secrets(token_type: str, app_token: str, id: str, host: str) -> requests.Response:
    """
    Fetch secrets from Phase KMS.

    Args:
        app_token (str): The token for the application.
        id (str): The environment ID.

    Returns:
        requests.Response: The HTTP response from the Phase KMS.
    """

    headers = {
        "Authorization": f"Bearer {token_type.capitalize()} {app_token}",
        "Environment": id
    }

    URL =  f"{host}/secrets/"

    try:
        response = requests.get(URL, headers=headers, verify=VERIFY_SSL)
        handle_request_errors(response)
        return response
    except requests.exceptions.ConnectionError as e:
        handle_connection_error(e)
    except requests.exceptions.SSLError as e:
        handle_ssl_error(e)


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

    headers = {
        "Authorization": f"Bearer {token_type.capitalize()} {app_token}",
        "Environment": environment_id
    }

    data = {
        "secrets": secrets
    }

    URL =  f"{host}/secrets/"

    try:
        response = requests.post(URL, headers=headers, json=data, verify=VERIFY_SSL)
        handle_request_errors(response)
        return response
    except requests.exceptions.ConnectionError as e:
        handle_connection_error(e)
    except requests.exceptions.SSLError as e:
        handle_ssl_error(e)


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

    headers = {
        "Authorization": f"Bearer {token_type.capitalize()} {app_token}",
        "Environment": environment_id
    }

    data = {
        "secrets": secrets
    }

    URL =  f"{host}/secrets/"


    try:
        response = requests.put(URL, headers=headers, json=data, verify=VERIFY_SSL)
        handle_request_errors(response)
        return response
    except requests.exceptions.ConnectionError as e:
        handle_connection_error(e)
    except requests.exceptions.SSLError as e:
        handle_ssl_error(e)


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

    headers = {
        "Authorization": f"Bearer {token_type.capitalize()} {app_token}",
        "Environment": environment_id
    }

    data = {
        "secrets": secret_ids
    }

    URL =  f"{host}/secrets/"

    try:
        response = requests.delete(URL, headers=headers, json=data, verify=VERIFY_SSL)
        handle_request_errors(response)
        return response
    except requests.exceptions.ConnectionError as e:
        handle_connection_error(e)
    except requests.exceptions.SSLError as e:
        handle_ssl_error(e)
