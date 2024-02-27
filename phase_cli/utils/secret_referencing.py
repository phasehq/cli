import re
from typing import Dict, List
from phase_cli.exceptions import EnvironmentNotFoundException
from phase_cli.utils.const import SECRET_REF_REGEX

"""
    Secret Referencing Syntax:

    This documentation explains the syntax used for referencing secrets within the configuration. 
    Secrets can be referenced both locally (within the same environment) and across different environments, 
    with or without specifying a path.

    Syntax Patterns:

    1. Local Reference (Root Path):
        Syntax: `${KEY}`
        - Environment: Same as the current environment.
        - Path: Root path (`/`).
        - Secret Key: `KEY`
        - Description: References a secret named `KEY` in the root path of the current environment.

    2. Cross-Environment Reference (Root Path):
        Syntax: `${staging.DEBUG}`
        - Environment: Different environment (e.g., `dev`).
        - Path: Root path (`/`) of the specified environment.
        - Secret Key: `DEBUG`
        - Description: References a secret named `DEBUG` in the root path of the `staging` environment.

    3. Cross-Environment Reference (Specific Path):
        Syntax: `${prod./frontend/SECRET_KEY}`
        - Environment: Different environment (e.g., `prod`).
        - Path: Specifies a path within the environment (`/frontend/`).
        - Secret Key: `SECRET_KEY`
        - Description: References a secret named `SECRET_KEY` located at `/frontend/` in the `prod` environment.

    4. Local Reference (Specified Path):
        Syntax: `${/backend/payments/STRIPE_KEY}`
        - Environment: Same as the current environment.
        - Path: Specifies a path within the environment (`/backend/payments/`).
        - Secret Key: `STRIPE_KEY`
        - Description: References a secret named `STRIPE_KEY` located at `/backend/payments/` in the current environment.

    Note:
    The syntax allows for flexible secret management, enabling both straightforward local references and more complex cross-environment references.
"""


def resolve_secret_reference(ref: str, secrets_dict: Dict[str, Dict[str, Dict[str, str]]], phase: 'Phase', current_application_name: str, current_env_name: str) -> str:
    """
    Resolves a single secret reference to its actual value by fetching it from the specified environment.
    
    The function supports both local and cross-environment secret references, allowing for flexible secret management.
    Local references are identified by the absence of a dot '.' in the reference string, implying the current environment.
    Cross-environment references include an environment name, separated by a dot from the rest of the path.
    
    Args:
        ref (str): The secret reference string, which could be a local or cross-environment reference.
        current_env_name (str): The current environment name, used for resolving local references.
        phase ('Phase'): An instance of the Phase class to fetch secrets.
        
    Returns:
        str: The resolved secret value.
        
    Raises:
        ValueError: If the current environment name is not provided, or the secret is not found.
    """
    
    env_name = current_env_name
    path = "/" # Default root path
    key_name = ref

    # Parse the reference to identify environment, path, and secret key.
    if "." in ref:  # Cross-environment references, split by the first dot to get environment and the rest.
        parts = ref.split(".", 1)
        env_name, rest = parts[0], parts[1]
        last_slash_index = rest.rfind("/")
        if last_slash_index != -1:
            path = rest[:last_slash_index]
            key_name = rest[last_slash_index + 1:]
        else:
            key_name = rest
    elif "/" in ref:  # Local reference with specified path
        last_slash_index = ref.rfind("/")
        path = ref[:last_slash_index]
        key_name = ref[last_slash_index + 1:]

    # Adjust for leading slash in path if not present
    if not path.startswith("/"):
        path = "/" + path

    try:
        # Lookup with environment, path, and key
        if env_name in secrets_dict and path in secrets_dict[env_name] and key_name in secrets_dict[env_name][path]:
            return secrets_dict[env_name][path][key_name]
        else:
            # Handle fallback for cross-environment or missing secrets
            if env_name != current_env_name:
                fetched_secrets = phase.get(env_name=env_name, app_name=current_application_name, keys=[key_name], path=path)
                for secret in fetched_secrets:
                    if secret["key"] == key_name:
                        return secret["value"]
    except EnvironmentNotFoundException:
        pass

    # Return the reference as is if not resolved
    return f"${{{ref}}}"


def resolve_all_secrets(value: str, all_secrets: List[Dict[str, str]], phase: 'Phase', current_application_name: str, current_env_name: str) -> str:
    """
    Resolves all secret references within a given string to their actual values.
    
    This function is particularly useful for processing configuration strings or entire files that
    may contain multiple secret references. It iterates through each reference found in the input string,
    resolves it using `resolve_secret_reference`, and replaces the reference with the resolved value.
    
    Args:
        value (str): The input string containing one or more secret references.
        current_env_name (str): The current environment name for resolving local references.
        phase ('Phase'): An instance of the Phase class to fetch secrets.
        
    Returns:
        str: The input string with all secret references resolved to their actual values.
        
    Raises:
        ValueError: If the current environment name is not provided.
    """

    secrets_dict = {}
    for secret in all_secrets:
        env_name = secret['environment']
        path = secret['path']
        key = secret['key']
        if env_name not in secrets_dict:
            secrets_dict[env_name] = {}
        if path not in secrets_dict[env_name]:
            secrets_dict[env_name][path] = {}
        secrets_dict[env_name][path][key] = secret['value']
    
    refs = SECRET_REF_REGEX.findall(value)
    resolved_value = value
    # Resolve each found reference and replace it with resolved_secret_value.
    for ref in refs:
        resolved_secret_value = resolve_secret_reference(ref, secrets_dict, phase, current_application_name, current_env_name)
        resolved_value = resolved_value.replace(f"${{{ref}}}", resolved_secret_value)
    
    return resolved_value
