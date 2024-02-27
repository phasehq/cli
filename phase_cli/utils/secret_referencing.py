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


def resolve_secret_reference(ref: str, current_application_name: str, current_env_name: str, phase: 'Phase') -> str:
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
        
    # Parse the reference to identify environment, path, and secret key.
    if "." in ref:
        # For cross-environment references, split by the first dot to get environment and the rest.
        parts = ref.split(".", 1)
        env_name, rest = parts[0], parts[1]
    else:
        # For local references, use the current environment.
        env_name = current_env_name
        rest = ref

    # Determine the path and key name from the rest of the reference.
    last_slash_index = rest.rfind("/")
    if last_slash_index != -1:
        path = rest[:last_slash_index]
        key_name = rest[last_slash_index + 1:]
    else:
        path = "/"
        key_name = rest

    # Attempt to fetch the secret from the specified environment and path.
    try:
        secrets = phase.get(env_name=env_name, app_name=current_application_name, keys=[key_name], path=path)
    except EnvironmentNotFoundException:
        # Fallback to the current env if the named env cannot be resolved
        secrets = phase.get(env_name=current_env_name, app_name=current_application_name, keys=[key_name], path=path)

    
    for secret in secrets:
        if secret["key"] == key_name:
            # Return the secret value if found.
            return secret["value"]
    
    # Return the secret value as is if no reference could be resolved
    return ref
    
    
def resolve_all_secrets(value: str, current_application_name: str, current_env_name: str, phase: 'Phase') -> str:
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
    
    # Find all secret references in the input string.
    refs = SECRET_REF_REGEX.findall(value)
    resolved_value = value

    # Resolve each found reference and replace it in the input string.
    for ref in refs:
        resolved_secret_value = resolve_secret_reference(ref=ref, current_application_name=current_application_name, current_env_name=current_env_name, phase=phase)
        resolved_value = resolved_value.replace(f"${{{ref}}}", resolved_secret_value)
    
    return resolved_value