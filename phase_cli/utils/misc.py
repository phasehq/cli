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
import platform
import shutil

def parse_bool_flag(value) -> bool:
    """
    Parse common CLI boolean strings into a bool.
    Treats 'false', '0', 'no', 'off' (case-insensitive) as False.
    Everything else (including None) is True by default.
    """
    if isinstance(value, bool):
        return value
    if value is None:
        return True
    s = str(value).strip().lower()
    return s not in ('false', '0', 'no', 'off')

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
        return censored[:max_length - 6]
    
    return censored


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
        # Partition into static and dynamic for display control
        static_secrets = [s for s in secrets if not s.get("is_dynamic")]
        dynamic_secrets = [s for s in secrets if s.get("is_dynamic")]

        # Display the path and the number of secrets it contains
        path_node = root_tree.add(f"📁 Path: {path} - [bold magenta]{len(secrets)} Secrets[/]")
        table = Table(show_header=True, header_style="bold white", box=box.ROUNDED)

        # Calculate dynamic widths based on the secrets of the current path
        key_lengths = [len(secret.get("key", "")) for secret in secrets]
        # Include dynamic group header labels in width calculation
        for s in dynamic_secrets:
            group_label = f"⚡️ {s.get('dynamic_group', 'Dynamic Secret')}"
            key_lengths.append(len(group_label))
        max_key_length = max(key_lengths, default=min_key_width)
        key_width = max(min_key_width, min(max_key_length + 6, 40))
        value_width = max(console.width - key_width - 4, 20)

        table.add_column("KEY", width=key_width, no_wrap=True)
        table.add_column("VALUE", width=value_width, overflow="fold")

        for secret in static_secrets:
            key_display, value_display = format_secret_row(secret, value_width, show)
            table.add_row(key_display, value_display)

        # Insert dynamic secrets into the same table with a separator
        if dynamic_secrets:
            table.add_section()
            # Group dynamic secrets by their dynamic_group label
            groups = {}
            for s in dynamic_secrets:
                groups.setdefault(s.get("dynamic_group", "⚡️ Dynamic Secret"), []).append(s)

            for group_label, items in groups.items():
                # Group header row
                table.add_row(f"⚡️ {group_label}", "")
                for s in items:
                    value = s.get("value", "⚡️")
                    # When not showing, indicate that a lease needs to be created
                    if not show:
                        value = "****************"
                    table.add_row(s.get("key"), value)

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


def get_default_account_id(all_ids=False) -> Union[str, List[str]]:
    """
    Fetch the default account ID from the config file in PHASE_SECRETS_DIR.
    
    This function handles both user accounts (PATs) and service accounts (service tokens).

    Parameters:
    - all_ids (bool): If set to True, returns a list of all account IDs. Otherwise, returns the default account ID.

    Returns:
    - Union[str, List[str]]: The default account ID, or a list of all account IDs if all_ids is True.

    Raises:
    - ValueError: If the config file is not found or if the default account ID is missing.
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


def get_default_user_id(all_ids=False) -> Union[str, List[str]]:
    """
    Fetch the default user's ID from the config file in PHASE_SECRETS_DIR.
    
    DEPRECATED: Use get_default_account_id() instead for better compatibility with service accounts.
    This function is kept for backward compatibility.

    Parameters:
    - all_ids (bool): If set to True, returns a list of all user IDs. Otherwise, returns the default user's ID.

    Returns:
    - Union[str, List[str]]: The default user's ID, or a list of all user IDs if all_ids is True.

    Raises:
    - ValueError: If the config file is not found or if the default user's ID is missing.
    """
    return get_default_account_id(all_ids)


def get_default_user_org(config_file_path):
    """Extracts the organization name of the default user from a JSON config file."""
    if os.path.exists(config_file_path):
        with open(config_file_path, 'r') as file:
            config = json.load(file)
            default_user_id = config.get("default-user")
            for user in config.get("phase-users", []):
                if user["id"] == default_user_id:
                    return user["organization_name"]
    raise ValueError("Configuration file missing or default user not found.")


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


def phase_get_context(user_data, app_name=None, env_name=None, app_id=None):
    """
    Get the context (ID, name, and publicKey) for a specified application and environment or the default application and environment.
    
    Parameters:
    - user_data (dict): The user data from the API response.
    - app_name (str, optional): The name (or partial name) of the desired application.
    - env_name (str, optional): The name (or partial name) of the desired environment.
    - app_id (str, optional): The explicit application ID to use. Takes precedence over app_name if both are provided.
    
    Returns:
    - tuple: A tuple containing the application's name, application's ID, environment's name, environment's ID, and publicKey.
    
    Raises:
    - ValueError: If no matching application or environment is found.
    """
    # 1. Get the default app_id and env_name from .phase.json if no explicit app_id provided
    if not app_id and not app_name:
        config_data = find_phase_config()
        if config_data:
            default_env_name = config_data.get("defaultEnv")
            app_id = config_data.get("appId")
        else:
            default_env_name = "Development"
            app_id = None
    else:
        default_env_name = "Development"

    # 2. If env_name isn't explicitly provided, use the default
    env_name = env_name or default_env_name

    # 3. Match the application using app_id first, then fall back to app_name if app_id is not provided
    try:
        if app_id:  # app_id takes precedence
            application = next((app for app in user_data["apps"] if app["id"] == app_id), None)
            if not application:
                raise ValueError(f"🔍 No application found with ID: '{app_id}'.")
        elif app_name:  # only check app_name if app_id is not provided
            matching_apps = [app for app in user_data["apps"] if app_name.lower() in app["name"].lower()]
            if not matching_apps:
                raise ValueError(f"🔍 No application found with the name '{app_name}'.")
            # Sort matching applications by the length of their names, shorter names are likely to be more specific matches
            matching_apps.sort(key=lambda app: len(app["name"]))
            application = matching_apps[0]
        else:
            raise ValueError("🤔 No application context provided. Please run 'phase init' or pass the '--app' or '--app-id' flag.")

        # 4. Attempt to match environment with the exact name or a name that contains the env_name string
        environment = next((env for env in application["environment_keys"] if env_name.lower() in env["environment"]["name"].lower()), None)

        if not environment:
            raise EnvironmentNotFoundException(env_name)

        # Return application name, application ID, environment name, environment ID, and public key
        return (application["name"], application["id"], environment["environment"]["name"], environment["environment"]["id"], environment["identity_key"])
    except StopIteration:
        raise ValueError("🔍 Application or environment not found.")


def find_phase_config(max_depth=8):
    """
    Search for a .phase.json file in the current directory and parent directories.
    
    Parameters:
    - max_depth (int): Maximum number of parent directories to check. Can be overridden with PHASE_CONFIG_PARENT_DIR_SEARCH_DEPTH environment variable.
    
    Returns:
    - dict or None: The contents of the .phase.json file if found, None otherwise.
    """
    # Check for environment variable override for search depth
    try:
        env_depth = os.environ.get('PHASE_CONFIG_PARENT_DIR_SEARCH_DEPTH')
        if env_depth:
            max_depth = int(env_depth)
    except (ValueError, TypeError):
        # If conversion fails, keep using the default max_depth
        pass
    
    current_dir = os.getcwd()
    original_dir = current_dir
    
    # Try up to max_depth parent directories
    for _ in range(max_depth + 1):  # +1 to include current directory
        config_path = os.path.join(current_dir, PHASE_ENV_CONFIG)
        
        if os.path.exists(config_path):
            try:
                with open(config_path, 'r') as f:
                    config_data = json.load(f)
                # Only use this config if monorepoSupport is true or we're in the original directory
                if os.path.samefile(current_dir, original_dir) or config_data.get("monorepoSupport", False):
                    return config_data
            except (json.JSONDecodeError, FileNotFoundError, OSError):
                pass
        
        # Move up to the parent directory
        parent_dir = os.path.dirname(current_dir)
        
        # If we've reached the root directory, stop
        if parent_dir == current_dir:
            break
            
        current_dir = parent_dir
    
    return None


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


def clean_subprocess_env():
    """
    Create a clean environment for subprocess execution by removing PyInstaller library paths.
    
    PyInstaller bundles its own copies of system libraries which can interfere with 
    subprocess execution when spawned from a PyInstaller-built application.

    TODO: Considering filtering for: 
        '_MEIPASS',            # PyInstaller temporary directory
        '_MEIPASS2',           # PyInstaller temporary directory (alternative)
        'PYTHONPATH',          # Python module search path (can contain bundled modules)
    
    Returns:
        dict: A copy of os.environ with PyInstaller library paths removed.
        
    References:
        https://github.com/pyinstaller/pyinstaller/blob/34508a2cda1072718a81ef1d5a660ce89e62d295/doc/common-issues-and-pitfalls.rst
    """
    clean_env = os.environ.copy()
    
    # Remove PyInstaller library path variables that can cause conflicts
    pyinstaller_vars = [
        'LD_LIBRARY_PATH',     # Linux dynamic library path
        'DYLD_LIBRARY_PATH',   # macOS dynamic library path
    ]
    
    for var in pyinstaller_vars:
        clean_env.pop(var, None)
    
    return clean_env


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
            # Use clean environment to avoid library conflicts with bundled libraries
            clean_env = clean_subprocess_env()
            with open(os.devnull, 'w') as fnull:
                subprocess.run(cmd, stdout=fnull, stderr=fnull, check=True, env=clean_env)
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

# Phase Shell

def get_default_shell():
    """
    Determines the default shell to use based on the current platform and environment.
    
    Returns:
        list: A list containing the shell command and any arguments to pass to it.
    """
    system = platform.system()
    
    if system == "Windows":
        # On Windows, try to use PowerShell first, then cmd
        if shutil.which("pwsh"):  # PowerShell Core (cross-platform)
            return ["pwsh"]
        elif shutil.which("powershell"):
            return ["powershell"]
        else:
            return ["cmd"]
    else:
        # On Unix-like systems (Linux, macOS), use the SHELL environment variable
        shell = os.environ.get("SHELL")
        if shell and os.path.exists(shell):
            return [shell]
        
        # Fall back to common shells in order of preference
        for sh in ["/bin/zsh", "/bin/bash", "/bin/sh"]:
            if os.path.exists(sh):
                return [sh]
    
    return None  # No suitable shell found

def get_shell_command(shell_type):
    """
    Get the command to launch the specified shell type.
    
    Args:
        shell_type (str): The type of shell to launch (bash, zsh, fish, powershell, etc.)
        
    Returns:
        list: A list containing the shell command and any arguments to pass to it.
    """
    shell_type = shell_type.lower()
    
    # Common shell mappings
    shell_map = {
        "bash": ["bash"],
        "zsh": ["zsh"],
        "fish": ["fish"],
        "powershell": ["powershell"],
        "pwsh": ["pwsh"],  # Cross-platform PowerShell Core
        "cmd": ["cmd"],
        "sh": ["sh"]
    }
    
    if shell_type in shell_map:
        shell_cmd = shell_map[shell_type]
        
        # Check if the shell executable exists
        shell_path = shutil.which(shell_cmd[0])
        if shell_path:
            return shell_cmd
        else:
            return None
    
    return None  # Unsupported shell type
