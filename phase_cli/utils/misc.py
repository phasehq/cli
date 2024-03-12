import os
import platform
import subprocess
import webbrowser
import getpass
import json
from phase_cli.exceptions import EnvironmentNotFoundException
from rich.table import Table
from rich.tree import Tree
from rich.console import Console
from rich import box
from rich.box import ROUNDED
from urllib.parse import urlparse
from typing import Union, List
from phase_cli.utils.const import __version__, PHASE_ENV_CONFIG, PHASE_CLOUD_API_HOST, PHASE_SECRETS_DIR, cross_env_pattern, local_ref_pattern


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

def get_default_user_token() -> str:
    """
    Fetch the default user's personal access token from the config file in PHASE_SECRETS_DIR.

    Returns:
    - str: The default user's personal access token.

    Raises:
    - ValueError: If the config file is not found, the default user's ID is missing, or the token is not set.
    """
    config_file_path = os.path.join(PHASE_SECRETS_DIR, 'config.json')
    
    if not os.path.exists(config_file_path):
        raise ValueError("Config file not found. Please login with phase auth or supply a PHASE_SERVICE_TOKEN as an environment variable.")
    
    with open(config_file_path, 'r') as f:
        config_data = json.load(f)

    default_user_id = config_data.get("default-user")
    if not default_user_id:
        raise ValueError("Default user ID is missing in the config file.")

    for user in config_data.get("phase-users", []):
        if user['id'] == default_user_id:
            token = user.get("token")
            if not token:
                raise ValueError(f"Token for the default user (ID: {default_user_id}) is not found in the config file.")
            return token

    raise ValueError("Default user not found in the config file.")


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
        app_name_from_config = config_data.get("phaseApp")
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
                raise ValueError(f"🔍 No application found with the name '{app_name_from_config}' and ID: '{app_id}'.")
        else:
            raise ValueError("🤔 No application context provided. Please run 'phase init' or pass the '--app' flag followed by your application name.")

        # 4. Attempt to match environment with the exact name or a name that contains the env_name string
        environment = next((env for env in application["environment_keys"] if env_name.lower() in env["environment"]["name"].lower()), None)

        if not environment:
            raise EnvironmentNotFoundException(env_name)

        # Return application name, application ID, environment name, environment ID, and public key
        return (application["name"], application["id"], environment["environment"]["name"], environment["environment"]["id"], environment["identity_key"])
    except StopIteration:
        raise ValueError("🔍 Application or environment not found.")


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