from phase_cli.utils.const import SECRET_REF_REGEX


def resolve_secret_reference(ref, current_env_name, phase, env_name=None, phase_app=None):
    """
    Parses and resolves a secret reference within the given or current environment and path. This function 
    supports resolving both local and cross-environment secret references, including those that specify a path.

    Args:
        ref (str): The secret reference to be resolved. It can be in the form of 'KEY', 'env.KEY', or 'env./path/to/KEY'.
        current_env_name (str): The current environment name, used when the reference does not specify an environment.
        phase (Phase): An instance of the Phase class, used to fetch the secret value.
        env_name (str, optional): The environment name from which to fetch the secret. If not provided, the environment
                                  part of the `ref` or `current_env_name` is used.
        phase_app (str, optional): The Phase application name. Defaults to None. Currently not used but can be
                                   implemented for application-specific secret fetching logic.

    Returns:
        str: The resolved secret value.

    Design Decisions:
    - **Default Path Handling:** Initially, the path defaults to root ('/') if not explicitly specified in the reference.
      This design choice simplifies handling cases where secrets are stored at the root level.

    - **Environment and Path Parsing:** The function splits the reference into the environment and the rest (path and key),
      allowing for flexible reference formats. This design supports both local references (without environment) and
      cross-environment references (with environment and optional path).

    - **Path Formatting:** Ensures the path starts and ends with a slash ('/'), standardizing the path format for consistent
      fetching. This adjustment is crucial for accurately constructing the API request, regardless of how the reference
      was formatted by the user.

    - **Error Handling:** If the secret cannot be fetched (not found or other errors), the function raises a ValueError
      with detailed information. This explicit error handling aids in troubleshooting and ensures that unresolved references
      are quickly identified and corrected.

    - **Support for Local and Cross-Environment References:** By accommodating references that include environment names
      and paths, the function provides flexibility in referencing secrets across different environments and paths, enhancing
      the tool's usability in complex setups.
    """
    # Initial path defaults to root if not specified in the reference
    path = '/'
    
    # Split reference into environment and the rest (which includes path and key)
    if '.' in ref:
        env_name, rest = ref.split('.', 1)
        
        # Extract path and key name from the rest
        path_key_split = rest.rsplit('/', 1)
        if len(path_key_split) == 2:
            path, key_name = path_key_split
            # Adjust path to ensure it starts and ends with a slash
            if not path.startswith('/'):
                path = '/' + path
            if not path.endswith('/'):
                path += '/'
        else:
            # No path specified, use root, key is the remaining part
            key_name = rest
    else:
        # Local reference: use the current environment, check for path
        env_name = current_env_name
        if '/' in ref:
            path, key_name = ref.rsplit('/', 1)
            path += '/'  # Ensure path ends with a slash
        else:
            # No path specified, key is the reference itself
            key_name = ref

    # Fetch and return the secret value using the corrected path and environment
    secret = phase.get(env_name=env_name, app_name=phase_app, path=path, keys=[key_name])
    if secret:
        return secret[0]['value']
    else:
        raise ValueError(f"Secret '{key_name}' not found in environment '{env_name}', path '{path}'.")


def resolve_all_secrets(value, current_env_name, phase, env_name=None, phase_app=None):
    """
    Resolve all secret references in a given value.

    Args:
        value (str): The string containing secret references.
        current_env_name (str): The current environment name.
        phase (Phase): An instance of the Phase class.
        env_name (str, optional): The environment name. Defaults to None, meaning use current_env_name.
        phase_app (str, optional): The Phase application name. Defaults to None.

    Returns:
        str: The string with all secret references resolved.
    """
    matches = SECRET_REF_REGEX.findall(value)
    for ref in matches:
        resolved_value = resolve_secret_reference(ref, current_env_name, phase, env_name, phase_app)
        value = value.replace(f"${{{ref}}}", resolved_value)
    return value
