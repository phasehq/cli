from typing import Dict, List, Tuple, Optional, Set
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

    Caching:
    - To improve performance and avoid N x 2 network requests when resolving references, secrets are cached in-memory
    - `resolve_all_secrets` first seeds the cache from `all_secrets` and prefetches all combos
      required by the references found in `value` by calling `phase.get()` without keys.
    - `resolve_secret_reference` checks the provided `secrets_dict` for secrets,
      falls back to the cache, and returns the unresolved placeholder if still not found.
    - The cache is process-local and not persisted or invalidated; it only reduces repeated
      lookups within a single execution.
"""


# Keyed by (application, environment, path) → { key: value }
_SECRETS_CACHE: Dict[Tuple[str, str, str], Dict[str, str]] = {}
# Structure (values are decrypted plaintext):
# {
#     ("my_app", "production", "/frontend"): {
#         "SECRET_KEY": "backend_api_secret_key",
#         "DEBUG": "false"
#     },
#     ("my_app", "current", "/"): {
#         "KEY": "value1"
#     }
# }
#


def _normalize_path(path: Optional[str]) -> str:
    """Return a normalized path that always starts with '/' and defaults to '/'."""
    if not path:
        return "/"
    if not path.startswith("/"):
        return "/" + path
    return path


def _cache_key(app_name: str, env_name: str, path: Optional[str]) -> Tuple[str, str, str]:
    """Centralize path normalization so every cache access uses the exact same (app, env, normalized path) shape, avoiding subtle mismatches."""
    return (app_name, env_name, _normalize_path(path))


def _prime_cache_from_list(secrets: List[Dict], fallback_app_name: str) -> None:
    """Seed the cache using secrets already available in memory.

    Each secret must minimally include: key, value, environment, path; application is optional
    and will default to `fallback_app_name` when not present.
    """
    for secret in secrets:
        app = secret.get("application") or fallback_app_name
        env = secret.get("environment")
        path = secret.get("path", "/")
        key = secret.get("key")
        value = secret.get("value")
        if not (app and env and key):
            continue
        ck = _cache_key(app, env, path)
        if ck not in _SECRETS_CACHE:
            _SECRETS_CACHE[ck] = {}
        _SECRETS_CACHE[ck][key] = value


def _ensure_cached(phase: 'Phase', app_name: str, env_name: str, path: Optional[str]) -> None:
    """Ensure the cache contains all secrets for (app, env, path).

    This fetches the entire bucket once per (application, environment, path) combo using
    `phase.get(..., keys=None, path=...)`. Subsequent calls for the same combo are no-ops.
    """
    ck = _cache_key(app_name, env_name, path)
    if ck in _SECRETS_CACHE:
        return
    try:
        fetched = phase.get(env_name=env_name, app_name=app_name, keys=None, path=_normalize_path(path))
    except EnvironmentNotFoundException:
        return
    bucket: Dict[str, str] = {}
    for secret in fetched or []:
        key = secret.get("key")
        value = secret.get("value")
        if key is not None:
            bucket[key] = value
    _SECRETS_CACHE[ck] = bucket


def _get_from_cache(app_name: str, env_name: str, path: Optional[str], key_name: str) -> Optional[str]:
    """Return a secret's value from the in-memory cache, if present."""
    ck = _cache_key(app_name, env_name, path)
    bucket = _SECRETS_CACHE.get(ck)
    if bucket is None:
        return None
    return bucket.get(key_name)


def _find_env_key_case_insensitive(secrets_dict: Dict[str, Dict[str, Dict[str, str]]], env_name: str) -> Optional[str]:
    """Find the appropriate environment key in secrets_dict for the given env_name.

    Tries exact match first, then case-insensitive exact match, and finally
    falls back to partial, case-insensitive containment (both directions).
    """
    # Exact match
    if env_name in secrets_dict:
        return env_name

    # Case-insensitive exact match
    lower_to_actual = {k.lower(): k for k in secrets_dict.keys()}
    candidate = lower_to_actual.get(env_name.lower())
    if candidate:
        return candidate

    # Partial match (prefer shorter names to mimic existing selection heuristics)
    env_lower = env_name.lower()
    partials = [
        k for k in secrets_dict.keys()
        if env_lower in k.lower() or k.lower() in env_lower
    ]
    if partials:
        return sorted(partials, key=lambda x: len(x))[0]

    return None


def _parse_reference_context(ref: str, current_application_name: str, current_env_name: str) -> Tuple[str, str, str, str]:
    """Parse a secret reference and return (app_name, env_name, path, key_name).

    Falls back to current app/env when they are not specified in the reference.
    """
    app_name = current_application_name
    env_name = current_env_name
    ref_body = ref
    if "::" in ref_body:
        parts = ref_body.split("::", 1)
        app_name, ref_body = parts[0], parts[1]
    if "." in ref_body:
        parts = ref_body.split(".", 1)
        env_name, ref_body = parts[0], parts[1]
    path, key_name = split_path_and_key(ref_body)
    return app_name, env_name, path, key_name


def _lookup_in_memory_value(
    secrets_dict: Dict[str, Dict[str, Dict[str, str]]],
    env_name: str,
    path: str,
    key_name: str,
    current_env_name: str,
) -> Optional[str]:
    """Lookup a secret value from the provided in-memory dict with case-insensitive env matching.

    Also supports local root-path fallback for current environment when path is '/'.
    """
    env_lookup_key = _find_env_key_case_insensitive(secrets_dict, env_name)
    if not env_lookup_key:
        return None
    env_bucket = secrets_dict.get(env_lookup_key) or {}
    if key_name in env_bucket.get(path, {}):
        return env_bucket[path][key_name]
    if path == "/" and env_name.lower() == current_env_name.lower() and key_name in env_bucket.get("/", {}):
        return env_bucket["/"][key_name]
    return None


def _ensure_cached_for_env_variants(
    phase: 'Phase',
    app_name: str,
    env_name: str,
    path: str,
    secrets_dict: Dict[str, Dict[str, Dict[str, str]]],
) -> None:
    """Prefetch cache for (app, env, path) and the closest in-memory env match if different."""
    _ensure_cached(phase, app_name, env_name, path)
    env_lookup_key = _find_env_key_case_insensitive(secrets_dict, env_name)
    if env_lookup_key and env_lookup_key != env_name:
        _ensure_cached(phase, app_name, env_lookup_key, path)


def split_path_and_key(ref: str) -> Tuple[str, str]:
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
    original_ref = ref
    app_name, env_name, path, key_name = _parse_reference_context(ref, current_application_name, current_env_name)

    # Try in-memory dict first
    in_mem = _lookup_in_memory_value(secrets_dict, env_name, path, key_name, current_env_name)
    if in_mem is not None:
        return in_mem

    # Ensure caches for both original and matched env variants, then try cache
    _ensure_cached_for_env_variants(phase, app_name, env_name, path, secrets_dict)
    cached_value = _get_from_cache(app_name, env_name, path, key_name)
    if cached_value is None:
        env_lookup_key = _find_env_key_case_insensitive(secrets_dict, env_name)
        if env_lookup_key and env_lookup_key != env_name:
            cached_value = _get_from_cache(app_name, env_lookup_key, path, key_name)
    if cached_value is not None:
        return cached_value

    return f"${{{original_ref}}}"


def resolve_all_secrets(value: str, all_secrets: List[Dict[str, str]], phase: 'Phase', current_application_name: str, current_env_name: str, _visited: Optional[Set[str]] = None) -> str:
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

    secrets_dict: Dict[str, Dict[str, Dict[str, str]]] = {}
    _prime_cache_from_list(all_secrets, fallback_app_name=current_application_name)
    for secret in all_secrets:
        env_bucket = secrets_dict.setdefault(secret['environment'], {})
        path_bucket = env_bucket.setdefault(secret['path'], {})
        path_bucket[secret['key']] = secret['value']
    
    refs = SECRET_REF_REGEX.findall(value)
    # Prefetch caches for unique (app, env, path) combos
    seen_combos: Set[Tuple[str, str, str]] = set()
    for ref in refs:
        app_name, env_name, path, _ = _parse_reference_context(ref, current_application_name, current_env_name)
        combo = (app_name, env_name, path)
        if combo in seen_combos:
            continue
        seen_combos.add(combo)
        _ensure_cached_for_env_variants(phase, app_name, env_name, path, secrets_dict)
    resolved_value = value
    # Resolve each found reference and replace it with resolved_secret_value.
    _visited = _visited or set()
    for ref in refs:
        app_name, env_name, path, key_name = _parse_reference_context(ref, current_application_name, current_env_name)
        canonical = f"{app_name}|{env_name}|{path}|{key_name}"
        if canonical in _visited:
            # Leave placeholder unresolved to break potential cycles
            continue
        _visited.add(canonical)

        resolved_secret_value = resolve_secret_reference(ref, secrets_dict, phase, current_application_name, current_env_name)

        # If we successfully resolved to some value that itself contains references, resolve them recursively
        if resolved_secret_value != f"${{{ref}}}" and SECRET_REF_REGEX.search(resolved_secret_value):
            resolved_secret_value = resolve_all_secrets(
                value=resolved_secret_value,
                all_secrets=all_secrets,
                phase=phase,
                current_application_name=app_name,
                current_env_name=env_name,
                _visited=_visited,
            )
        resolved_value = resolved_value.replace(f"${{{ref}}}", resolved_secret_value)
    
    return resolved_value
