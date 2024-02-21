import sys
import getpass
from phase_cli.utils.phase_io import Phase
from phase_cli.cmd.secrets.list import phase_list_secrets
from phase_cli.utils.crypto import generate_random_secret
from rich.console import Console
from typing import List, Tuple
import requests

def phase_secrets_create(key=None, env_name=None, phase_app=None, random_type=None, random_length=None, path='/'):
    """
    Creates a new secret, encrypts it, and sync it with the Phase, with support for specifying a path.

    Args:
        key (str, optional): The key of the new secret. Defaults to None.
        env_name (str, optional): The name of the environment where the secret will be created. Defaults to None.
        phase_app (str, optional): The name of the Phase application. Defaults to None.
        random_type (str, optional): The type of random secret to generate (e.g., 'hex', 'alphanumeric'). Defaults to None.
        random_length (int, optional): The length of the random secret. Defaults to 32.
        path (str, optional): The path under which to store the secrets. Defaults to the root path '/'.
    """

    # Initialize the Phase class
    phase = Phase()
    console = Console()

    # If the key is not passed as an argument, prompt user for input
    if key is None:
        key = input("🗝️  Please enter the key: ")
    key = key.upper()

    # Check if the secret already exists
    try:
        secrets_data = phase.get(env_name=env_name, keys=[key], app_name=phase_app, path=path)
        secret_data = next((secret for secret in secrets_data if secret["key"] == key), None)
        if secret_data:
            # Updated to include path in the optional flags message
            print(f"🗝️  Secret with key '{key}' already exists at path '{path}'. Use 'phase secrets update' to change it's value.")
            return
    except ValueError as e:
        console.log(f"Error: {e}")
        return

    # Generate a random value or get value from user
    if random_type:
        # Check if length is specified for key128 or key256
        if random_type in ['key128', 'key256'] and random_length != 32:
            print("⚠️\u200A Warning: The length argument is ignored for 'key128' and 'key256'. Using default lengths.")

        try:
            value = generate_random_secret(random_type, random_length)
        except ValueError as e:
            console.log(f"Error: {e}")
            return
    else:
        # Check if input is being piped
        if sys.stdin.isatty():
            value = getpass.getpass("✨ Please enter the value (hidden): ")
        else:
            value = sys.stdin.read().strip()

    try:
        # Encrypt and send secret to the backend using the `create` method with path support
        response = phase.create(key_value_pairs=[(key, value)], env_name=env_name, app_name=phase_app, path=path)

        # Check the response status code
        if response.status_code == 200:
            # Call the phase_list_secrets function to list the secrets
            phase_list_secrets(show=False, phase_app=phase_app, env_name=env_name, path=path)
        else:
            # Print an error message if the response status code indicates an error
            print(f"Error: Failed to create secret. HTTP Status Code: {response.status_code}")

    except ValueError as e:
        console.log(f"Error: {e}")
