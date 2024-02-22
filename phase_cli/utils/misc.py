import os
import platform
import subprocess
import webbrowser
import getpass
import json
from rich.table import Table
from rich.tree import Tree
from rich.console import Console
from rich import box
from rich.box import ROUNDED
from urllib.parse import urlparse
from typing import Union, List
from phase_cli.utils.const import __version__, SECRET_REF_REGEX, PHASE_ENV_CONFIG, PHASE_CLOUD_API_HOST, PHASE_SECRETS_DIR, cross_env_pattern, local_ref_pattern


def get_terminal_width():
    """
    Get the width of the terminal window.
    If an OSError occurs (e.g., when running under 'watch' or piping output to a file),
    a default width of 80 is assumed.
    """
    try:
        return os.get_terminal_size().columns
    except OSError:
        return 80


def print_phase_links():
    """
    Print a beautiful welcome message inviting users to Phase's community and GitHub repository.
    """
    # Calculate the dynamic width of the terminal for the separator line
    separator_line = "─" * get_terminal_width()
    
    print("\033[1;34m" + separator_line + "\033[0m")
    print("🙋 Need help?: \033[4mhttps://slack.phase.dev\033[0m")
    print("💻 Bug reports / feature requests: \033[4mhttps://github.com/phasehq/cli\033[0m")
    print("\033[1;34m" + separator_line + "\033[0m")


def sanitize_value(value):
    """Sanitize values by removing surrounding single or double quotes."""
    if value.startswith("'") and value.endswith("'"):
        return value[1:-1]
    elif value.startswith('"') and value.endswith('"'):
        return value[1:-1]
    return value


def censor_secret(secret, max_length):
    """
    Censor a secret to not exceed a certain length.
    Also includes legacy censoring logic.

    :param secret: The secret to be censored
    :param max_length: The maximum allowable length of the censored secret
    :return: The censored secret
    """
    # Legacy censoring logic
    if len(secret) <= 6:
        censored = '*' * len(secret)
    else:
        censored = secret[:3] + '*' * (len(secret) - 6) + secret[-3:]

    # Check for column width and truncate if necessary
    if len(censored) > max_length:
        return censored[:max_length - 3]
    
    return censored


# Tokenizing function
def tokenize(value):
    delimiters = [':', '@', '/', ' ']
    tokens = [value]
    for delimiter in delimiters:
        new_tokens = []
        for token in tokens:
            new_tokens.extend(token.split(delimiter))
        tokens = new_tokens
    return tokens


def render_tree_with_tables(data, show, console):
    """
    Organize secrets by path and render a table for each path within a tree structure,
    including application name, environment name, personal secret indicators,
    cross-environment, and local environment secret references.
    Utilizes censoring for secret values based on the 'show' parameter.

    Args:
        data: List of dictionaries containing keys, values, paths, overridden status, tags, comments, application, and environment.
        show: Whether to show the values or censor them.
        console: Instance of rich.console.Console for rendering.
    """
    if not data:
        console.print("No secrets to display.")
        return

    # Extract application and environment names from the first secret
    application_name = data[0]['application']
    environment_name = data[0]['environment']
    root_tree = Tree(f"🔮 Secrets for Application: [bold cyan]{application_name}[/], Environment: [bold green]{environment_name}[/]")

    # Organize secrets by path
    paths = {}
    for item in data:
        path = item.get("path", "/")
        if path not in paths:
            paths[path] = []
        paths[path].append(item)

    # Set a reasonable minimum width for the KEY column
    min_key_width = 15

    for path, secrets in sorted(paths.items()):
        # Display the path and the number of secrets it contains
        path_node = root_tree.add(f"📁 Path: {path} - [bold magenta]{len(secrets)} Secrets[/]")
        table = Table(show_header=True, header_style="bold white", box=box.ROUNDED)

        # Calculate dynamic widths based on the secrets of the current path
        max_key_length = max([len(secret.get("key", "")) for secret in secrets], default=min_key_width)
        key_width = max(min_key_width, min(max_key_length + 6, 40))
        value_width = max(console.width - key_width - 4, 20)

        table.add_column("KEY 🗝️", width=key_width, no_wrap=True)
        table.add_column("VALUE ✨", width=value_width, overflow="fold")

        for secret in secrets:
            key_display, value_display = format_secret_row(secret, value_width, show)
            table.add_row(key_display, value_display)

        path_node.add(table)

    console.print(root_tree)


def format_secret_row(secret, value_width, show):
    """
    Format the row for a secret to be displayed in the table.

    Args:
        secret: The secret data dictionary.
        value_width: The calculated width for the value column.
        show: Whether to show the values or censor them.

    Returns:
        A tuple containing the formatted key and value strings.
    """
    key = secret.get("key")
    value = secret.get("value", "")
    tags = " 🏷️" if secret.get("tags") else ""
    comment = " 💬" if secret.get("comment") else ""
    key_display = f"{key}{tags}{comment}"

    icon = '⛓️  ' if cross_env_pattern.search(value) else ''
    icon += '🔗 ' if local_ref_pattern.search(value) else ''

    personal_indicator = '🔏 ' if secret.get("overridden", False) else ''

    censored_value = censor_secret(value, value_width - len(icon) - len(personal_indicator)) if not show else value
    value_display = f"{icon}{personal_indicator}{censored_value}"

    return key_display, value_display


def validate_url(url):
    parsed_url = urlparse(url)
    return all([
        parsed_url.scheme,   # Scheme should be present (e.g., "https")
        parsed_url.netloc,   # Network location (e.g., "example.com") should be present
    ])


def get_default_user_host() -> str:
    """
    Determine the Phase host based on the available environment variables or the local configuration file.
    
    The function operates in the following order of preference:
    1. If the `PHASE_SERVICE_TOKEN` environment variable is available:
        a. Returns the value of the `PHASE_HOST` environment variable if set.
        b. If `PHASE_HOST` is not set, returns the default `PHASE_CLOUD_API_HOST`.
    2. If the `PHASE_SERVICE_TOKEN` environment variable is not available:
        a. Reads the local `config.json` file to retrieve the host for the default user.

    Parameters:
        None

    Returns:
        str: The Phase host, determined based on the environment variables or local configuration.

    Raises:
        ValueError: 
            - If the `config.json` file does not exist and the `PHASE_SERVICE_TOKEN` environment variable is not set.
            - If the default user's ID from the `config.json` does not correspond to any user entry in the file.

    Examples:
        >>> get_default_user_host()
        'https://console.phase.dev'  # This is just an example and the returned value might be different based on the actual environment and config.
    """

    # If PHASE_SERVICE_TOKEN is available
    if os.environ.get('PHASE_SERVICE_TOKEN'):
        return os.environ.get('PHASE_HOST', PHASE_CLOUD_API_HOST)

    config_file_path = os.path.join(PHASE_SECRETS_DIR, 'config.json')
    
    # Check if config.json exists
    if not os.path.exists(config_file_path):
        raise ValueError("Config file not found and no PHASE_SERVICE_TOKEN environment variable set.")
    
    with open(config_file_path, 'r') as f:
        config_data = json.load(f)

    default_user_id = config_data.get("default-user")
    
    for user in config_data.get("phase-users", []):
        if user["id"] == default_user_id:
            return user["host"]

    raise ValueError(f"No user found in config.json with id: {default_user_id}.")


def get_default_user_id(all_ids=False) -> Union[str, List[str]]:
    """
    Fetch the default user's ID from the config file in PHASE_SECRETS_DIR.

    Parameters:
    - all_ids (bool): If set to True, returns a list of all user IDs. Otherwise, returns the default user's ID.

    Returns:
    - Union[str, List[str]]: The default user's ID, or a list of all user IDs if all_ids is True.

    Raises:
    - ValueError: If the config file is not found or if the default user's ID is missing.
    """
    config_file_path = os.path.join(PHASE_SECRETS_DIR, 'config.json')
    
    if not os.path.exists(config_file_path):
        raise ValueError("Please login with phase auth or supply a PHASE_SERVICE_TOKEN as an environment variable")
    
    with open(config_file_path, 'r') as f:
        config_data = json.load(f)

    if all_ids:
        return [user['id'] for user in config_data.get('phase-users', [])]
    else:
        return config_data.get("default-user")


def phase_get_context(user_data, app_name=None, env_name=None):
    """
    Get the context (ID, name, and publicKey) for a specified application and environment or the default application and environment.

    Parameters:
    - user_data (dict): The user data from the API response.
    - app_name (str, optional): The name (or partial name) of the desired application.
    - env_name (str, optional): The name (or partial name) of the desired environment.

    Returns:
    - tuple: A tuple containing the application's name, application's ID, environment's name, environment's ID, and publicKey.

    Raises:
    - ValueError: If no matching application or environment is found.
    """
    app_id = None
    # 1. Get the default app_id and env_name from .phase.json if available
    try:
        with open(PHASE_ENV_CONFIG, 'r') as f:
            config_data = json.load(f)
        default_env_name = config_data.get("defaultEnv")
        app_id = config_data.get("appId")
    except FileNotFoundError:
        default_env_name = "Development"
        app_id = None

    # 2. If env_name isn't explicitly provided, use the default
    env_name = env_name or default_env_name

    # 3. Match the application using app_id or find the best match for partial app_name
    try:
        if app_name:
            matching_apps = [app for app in user_data["apps"] if app_name.lower() in app["name"].lower()]
            if not matching_apps:
                raise ValueError(f"🔍 No application found with the name '{app_name}'.")
            # Sort matching applications by the length of their names, shorter names are likely to be more specific matches
            matching_apps.sort(key=lambda app: len(app["name"]))
            application = matching_apps[0]
        elif app_id:
            application = next((app for app in user_data["apps"] if app["id"] == app_id), None)
            if not application:
                raise ValueError(f"No application found with the ID '{app_id}'.")
        else:
            raise ValueError("🤔 No application context provided. Please run 'phase init' or pass the '--app' flag followed by your application name.")

        # 4. Attempt to match environment with the exact name or a name that contains the env_name string
        environment = next((env for env in application["environment_keys"] if env_name.lower() in env["environment"]["name"].lower()), None)

        if not environment:
            raise ValueError(f"⚠️\u200A Warning: The environment '{env_name}' either does not exist or you do not have access to it.")

        # Return application name, application ID, environment name, environment ID, and public key
        return (application["name"], application["id"], environment["environment"]["name"], environment["environment"]["id"], environment["identity_key"])
    except StopIteration:
        raise ValueError("🔍 Application or environment not found.")


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


def normalize_tag(tag):
    """
    Normalize a tag by replacing underscores with spaces.

    Args:
        tag (str): The tag to normalize.

    Returns:
        str: The normalized tag.
    """
    return tag.replace('_', ' ').lower()


def tag_matches(secret_tags, user_tag):
    """
    Check if the user-provided tag partially matches any of the secret tags.

    Args:
        secret_tags (list): The list of tags associated with a secret.
        user_tag (str): The user-provided tag to match.

    Returns:
        bool: True if there's a partial match, False otherwise.
    """
    normalized_user_tag = normalize_tag(user_tag)
    for tag in secret_tags:
        normalized_secret_tag = normalize_tag(tag)
        if normalized_user_tag in normalized_secret_tag:
            return True
    return False

def open_browser(url):
    """Open a URL in the default browser, with fallbacks and error handling."""
    try:
        # Try to open the URL in a web browser
        webbrowser.open(url, new=2)
    except webbrowser.Error:
        try:
            # Determine the right command based on the OS
            if platform.system() == "Windows":
                cmd = ['start', url]
            elif platform.system() == "Darwin":
                cmd = ['open', url]
            else:  # Assume Linux or other Unix-like OS
                cmd = ['xdg-open', url]

            # Suppress output by redirecting to devnull
            with open(os.devnull, 'w') as fnull:
                subprocess.run(cmd, stdout=fnull, stderr=fnull, check=True)
        except Exception as e:
            # If all methods fail, instruct the user to open the URL manually
            print(f"Unable to automatically open the Phase Console in your default web browser")


def get_user_agent():
    """
    Constructs a user agent string containing information about the CLI's version, 
    the operating system, its version, its architecture, and the local username with machine name.
    
    Returns:
        str: The constructed user agent string.
    """

    details = []
    
    # Get CLI version
    try:
        cli_version = f"phase-cli/{__version__}"
        details.append(cli_version)
    except:
        pass

    # Get OS and version
    try:
        os_type = platform.system()  # e.g., Windows, Linux, Darwin (for macOS)
        os_version = platform.release()
        details.append(f"{os_type} {os_version}")
    except:
        pass

    # Get architecture
    try:
        architecture = platform.machine()
        details.append(architecture)
    except:
        pass

    # Get username and hostname
    try:
        username = getpass.getuser()
        hostname = platform.node()
        user_host_string = f"{username}@{hostname}"
        details.append(user_host_string)
    except:
        pass

    user_agent_str = ' '.join(details)
    return user_agent_str