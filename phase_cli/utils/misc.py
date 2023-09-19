import os
import platform
import sys
import json
import re
from typing import Union, List
from phase_cli.utils.const import __version__, PHASE_ENV_CONFIG, PHASE_SECRETS_DIR, cross_env_pattern, local_ref_pattern

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
        return censored[:max_length - 3]
    
    return censored


def render_table(data, show=False, min_key_width=20):
    """
    Render a table of key-value pairs.

    :param data: List of dictionaries containing keys and values
    :param show: Whether to show the values or censor them
    :param min_key_width: Minimum width for the "Key" column
    """
    
    # Find the length of the longest key
    longest_key_length = max([len(item.get("key", "")) for item in data], default=0)
    
    # Set min_key_width to be the length of the longest key plus a buffer of 3,
    # but not less than the provided minimum
    min_key_width = max(longest_key_length + 3, min_key_width)
    
    terminal_width = get_terminal_width()
    value_width = terminal_width - min_key_width - 4  # Deducting for spaces and pipe

    # Print the headers
    print(f'{"KEY 🗝️":<{min_key_width}}  | {"VALUE ✨":<{value_width}}')
    print('-' * (min_key_width + value_width + 3))  # +3 accounts for spaces and pipe

    # If data is empty, just return after printing headers
    if not data:
        return
    
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

    # Print the rows
    for item in data:
        key = item.get("key")
        value = item.get("value")
        icon = ''
        
        # Tokenize value and check each token for references
        tokens = tokenize(value)
        cross_env_detected = any(cross_env_pattern.match(token) for token in tokens)
        local_ref_detected = any(local_ref_pattern.match(token) for token in tokens if not cross_env_pattern.match(token))

        # Set icon based on detected references
        if cross_env_detected:
            icon += '⛓️` '
        if local_ref_detected:
            icon += '🔗 '

        censored_value = censor_secret(value, value_width-len(icon))

        # Include the icon before the value or censored value
        displayed_value = icon + (value if show else censored_value)

        print(f'{key:<{min_key_width}} | {displayed_value:<{value_width}}')


def get_default_user_host() -> str:
    """
    Check if PHASE_HOST environment variable is set. If not, parse the config.json 
    in PHASE_SECRETS_DIR, find the host corresponding to the default-user's id and return it.

    Returns:
        str: The host value either from the environment variable or from the config file.

    Raises:
        ValueError: If the default-user's id does not match any user in phase-users 
        or if the config file is not found and the environment variable is not set.
    """
    
    # Check if PHASE_HOST environment variable is set
    phase_host_env = os.environ.get('PHASE_HOST')
    if phase_host_env:
        return phase_host_env

    config_file_path = os.path.join(PHASE_SECRETS_DIR, 'config.json')
    
    # Check if config.json exists
    if not os.path.exists(config_file_path):
        raise ValueError("PHASE_HOST missing: Please set PHASE_HOST environment variable or login via phase auth")
    
    with open(config_file_path, 'r') as f:
        config_data = json.load(f)

    default_user_id = config_data.get("default-user")
    
    for user in config_data.get("phase-users", []):
        if user["id"] == default_user_id:
            return user["host"]

    raise ValueError(f"No user found in config.json with id: {default_user_id} and no PHASE_HOST environment variable set.")


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
        raise ValueError("No config found in '~/.phase/secrets/config.json'. Please login with phase auth")
    
    with open(config_file_path, 'r') as f:
        config_data = json.load(f)

    if all_ids:
        return [user['id'] for user in config_data.get('phase-users', [])]
    else:
        return config_data.get("default-user")


def phase_get_context(user_data, app_name=None, env_name=None):
    """
    Get the context (ID and publicKey) for a specified application and environment or the default application and environment.

    Parameters:
    - user_data (dict): The user data from the API response.
    - app_name (str, optional): The name of the desired application.
    - env_name (str, optional): The name (or partial name) of the desired environment.

    Returns:
    - tuple: A tuple containing the application's ID, environment's ID and publicKey.

    Raises:
    - ValueError: If no matching application or environment is found or multiple environments match the given name.
    """
    # Initialize app_id as null
    app_id = None
    
    # If env_name is not provided, fetch it from the .phase.json file
    if not env_name:
        try:
            with open(PHASE_ENV_CONFIG, 'r') as f:
                config_data = json.load(f)
            env_name = config_data["defaultEnv"]
            app_id = config_data.get("appId")
        except FileNotFoundError:
            raise FileNotFoundError(f"Phase app config not found. Please make sure you're in the correct directory or initialize using 'phase init'.")
    
    # If appId is provided, use it to find the desired application
    if app_id:
        application = next((app for app in user_data["apps"] if app["id"] == app_id), None)
    # If app_name is provided, use it to find the desired application
    elif app_name:
        application = next((app for app in user_data["apps"] if app["name"] == app_name), None)
    else:
        application = user_data["apps"][0]

    if not application:
        raise ValueError(f"No application matched using ID '{app_id}' or name '{app_name}'.")

    # Search for environments with names containing the env_name
    matching_envs = [env for env in application["environment_keys"] if env_name.lower() in env["environment"]["name"].lower()]
        
    # If more than one environment matches, raise an error
    if len(matching_envs) > 1:
        raise ValueError(f"Multiple environments matched '{env_name}' for application '{application['name']}': {[env['environment']['name'] for env in matching_envs]}.\nPlease specify the full environment name.")
    elif not matching_envs:
        raise ValueError(f"No environment matched '{env_name}' for application '{application['name']}'.")
    else:
        environment = matching_envs[0]

    return application["id"], environment["environment"]["id"], environment["identity_key"]


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
        username = os.getlogin()
        hostname = platform.node()
        user_host_string = f"{username}@{hostname}"
        details.append(user_host_string)
    except:
        pass

    user_agent_str = ' '.join(details)
    return user_agent_str