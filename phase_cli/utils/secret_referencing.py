from typing import Dict, List
from phase_cli.exceptions import EnvironmentNotFoundException
from phase_cli.utils.const import SECRET_REF_REGEX
from phase_cli.utils.phase_io import Phase

"""
    Secret Referencing Syntax:

    This documentation explains the syntax used for referencing secrets within the configuration. 
    Secrets can be referenced locally (within the same environment), across different environments, 
    and across different applications, with or without specifying a path.

    Syntax Patterns:

    1. Local Reference (Root Path):
        Syntax: `${KEY}`
        - Environment: Same as the current environment.
        - Path: Root path (`/`).
        - Secret Key: `KEY`
        - Description: References a secret named `KEY` in the root path of the current environment.

    2. Cross-Environment Reference (Root Path):
        Syntax: `${staging.DEBUG}`
        - Environment: Different environment (e.g., `staging`).
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

    5. Cross-Application Reference:
        Syntax: `${backend_api::production./frontend/SECRET_KEY}`
        - Application: Different application (e.g., `backend_api`).
        - Environment: Different environment (e.g., `production`).
        - Path: Specifies a path within the environment (`/frontend/`).
        - Secret Key: `SECRET_KEY`
        - Description: References a secret named `SECRET_KEY` located at `/frontend/` in the `production` environment of the `backend_api` application.

    Note:
    The syntax allows for flexible secret management, enabling local references, cross-environment references, and cross-application references.
"""


def split_path_and_key(ref: str) -> tuple:
    """
    Splits a reference string into path and key components.

    Args:
        ref (str): The reference string to split.

    Returns:
        tuple: A tuple containing the path and key.
    """
    last_slash_index = ref.rfind("/")
    if last_slash_index != -1:
        path = ref[:last_slash_index]
        key_name = ref[last_slash_index + 1:]
    else:
        path = "/"
        key_name = ref

    # Ensure path starts with a slash
    if not path.startswith("/"):
        path = "/" + path

    return path, key_name


def resolve_secret_reference(ref: str, secrets_dict: Dict[str, Dict[str, Dict[str, str]]], phase: 'Phase', current_application_name: str, current_env_name: str) -> str:
    """
    Resolves a single secret reference to its actual value by fetching it from the specified environment.
    
    The function supports local, cross-environment, and cross-application secret references, allowing for flexible secret management.
    Local references are identified by the absence of a dot '.' in the reference string, implying the current environment.
    Cross-environment references include an environment name, separated by a dot from the rest of the path.
    Cross-application references use '::' to separate the application name from the rest of the reference.
    
    Args:
        ref (str): The secret reference string, which could be a local, cross-environment, or cross-application reference.
        secrets_dict (Dict[str, Dict[str, Dict[str, str]]]): A dictionary containing known secrets.
        phase ('Phase'): An instance of the Phase class to fetch secrets.
        current_application_name (str): The name of the current application.
        current_env_name (str): The current environment name, used for resolving local references.
        
    Returns:
        str: The resolved secret value or the original reference if not resolved.
    """
    app_name = current_application_name
    env_name = current_env_name
    path = "/"  # Default root path
    key_name = ref

    # Check if this is a cross-application reference
    if "::" in ref:
        parts = ref.split("::", 1)
        app_name, ref = parts[0], parts[1]
        
    # Parse the reference to identify environment, path, and secret key.
    if "." in ref:  # Cross-environment references
        parts = ref.split(".", 1)
        env_name, rest = parts[0], parts[1]
        path, key_name = split_path_and_key(rest)
    else:  # Local reference
        path, key_name = split_path_and_key(ref)

    try:
        # Lookup with environment, path, and key
        if env_name in secrets_dict:
            # Try to find the secret in the exact path
            if path in secrets_dict[env_name] and key_name in secrets_dict[env_name][path]:
                return secrets_dict[env_name][path][key_name]
            
            # For local references, try to find the secret in the root path only if the original path was root
            if env_name == current_env_name and path == "/" and '/' in secrets_dict[env_name] and key_name in secrets_dict[env_name]['/']:
                return secrets_dict[env_name]['/'][key_name]

        # If the secret is not found in secrets_dict, try to fetch it from Phase
        fetched_secrets = phase.get(env_name=env_name, app_name=app_name, keys=[key_name], path=path)
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
        all_secrets (List[Dict[str, str]]): A list of all known secrets.
        phase ('Phase'): An instance of the Phase class to fetch secrets.
        current_application_name (str): The name of the current application.
        current_env_name (str): The current environment name for resolving local references.
        
    Returns:
        str: The input string with all secret references resolved to their actual values.
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
