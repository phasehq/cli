import os
import sys
import json
from typing import Union, List
from utils.const import PHASE_ENV_CONFIG, PHASE_SECRETS_DIR

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
    """
    Sanitize the value by stripping single quotes if they are present.
    """
    return value.strip("'")


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


def render_table(data, show=False, min_key_width=1):
    """
    Render a table of key-value pairs.

    :param data: List of dictionaries containing keys and values
    :param show: Whether to show the values or censor them
    :param min_key_width: Minimum width for the "Key" column
    """
    
    # Find the length of the longest key
    longest_key_length = max(len(item.get("key", "")) for item in data)
    
    # Set min_key_width to be the length of the longest key plus a buffer of 3,
    # but not less than 30 (or any other specified minimum)
    min_key_width = max(longest_key_length + 3, min_key_width)
    
    terminal_width = get_terminal_width()
    value_width = terminal_width - min_key_width - 4

    # Print the headers
    print(f'{"KEY 🗝️":<{min_key_width}}  | {"VALUE ✨":<{value_width}}')
    print('-' * (min_key_width + value_width))

    # Print the rows
    for item in data:
        key = item.get("key")
        value = item.get("value")
        censored_value = censor_secret(value, value_width)
        print(f'{key:<{min_key_width}} | {(value if show else censored_value):<{value_width}}')


def get_default_user_host() -> str:
    """
    Parse the config.json in PHASE_SECRETS_DIR, find the host corresponding to the default-user's id and return it.

    Returns:
        str: The host corresponding to the default-user's id.
    
    Raises:
        ValueError: If the default-user's id does not match any user in phase-users or if the config file is not found.
    """
    config_file_path = os.path.join(PHASE_SECRETS_DIR, 'config.json')
    
    # Check if config.json exists
    if not os.path.exists(config_file_path):
        raise ValueError("Config file not found in PHASE_SECRETS_DIR.")
    
    with open(config_file_path, 'r') as f:
        config_data = json.load(f)

    default_user_id = config_data.get("default-user")
    
    for user in config_data.get("phase-users", []):
        if user["id"] == default_user_id:
            return user["host"]

    raise ValueError(f"No user found in config.json with id: {default_user_id}")


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


def phase_get_context(env_name=None):
    """
    Get the context (ID and publicKey) for a specified environment or the default environment.

    Parameters:
    - env_name (str, optional): The name (or partial name) of the desired environment.

    Returns:
    - tuple: A tuple containing the environment's ID and publicKey.

    Raises:
    - FileNotFoundError: If the Phase app configuration file (.phase.json) is missing.
    - ValueError: If no matching environment is found or multiple environments match the given name.
    """
    try:
        with open(PHASE_ENV_CONFIG, 'r') as f:
            config_data = json.load(f)
    except FileNotFoundError:
        raise FileNotFoundError("Phase app config (\".phase.json\") not found. Please make sure you're in the correct directory or initialize using 'phase init'.")

    if env_name:
        # Search for environments with names containing the partial env_name
        matching_envs = [env for env in config_data["phaseEnvironments"] if env_name.lower() in env["env"].lower()]
        
        # If more than one environment matches, prompt the user to specify the full name
        if len(matching_envs) > 1:
            print(f"Multiple environments matched '{env_name}': {[env['env'] for env in matching_envs]}")
            print("Please specify the full environment name.")
            sys.exit(1)
        elif not matching_envs:
            raise ValueError(f"No environment matched '{env_name}'.")
        else:
            environment = matching_envs[0]
    else:
        # Use default environment
        default_env_id = config_data.get("defaultEnv")
        environment = next((env for env in config_data["phaseEnvironments"] if env["id"] == default_env_id), None)
    
    if not environment:
        raise ValueError("No matching environment found.")
    
    return environment["id"], environment["publicKey"]
