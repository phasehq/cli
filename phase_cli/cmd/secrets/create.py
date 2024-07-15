import sys
import getpass
from phase_cli.utils.phase_io import Phase
from phase_cli.cmd.secrets.list import phase_list_secrets
from phase_cli.utils.crypto import generate_random_secret
from rich.console import Console

def phase_secrets_create(key=None, env_name=None, phase_app=None, random_type=None, random_length=None, path='/', override=False):
    """
    Creates a new secret, encrypts it, and syncs it with the Phase, with support for specifying a path and overrides.

    Args:
        key (str, optional): The key of the new secret. Defaults to None.
        env_name (str, optional): The name of the environment where the secret will be created. Defaults to None.
        phase_app (str, optional): The name of the Phase application. Defaults to None.
        random_type (str, optional): The type of random secret to generate (e.g., 'hex', 'alphanumeric'). Defaults to None.
        random_length (int, optional): The length of the random secret. Defaults to 32.
        path (str, optional): The path under which to store the secrets. Defaults to the root path '/'.
        override (bool, optional): Whether to create an overridden secret. Defaults to False.
    """

    # Initialize the Phase class
    phase = Phase()
    console = Console()

    # If the key is not passed as an argument, prompt user for input
    if key is None:
        key = input("🗝️\u200A Please enter the key: ")

    # Replace spaces in the key with underscores
    key = key.replace(' ', '_').upper()

    # Generate a random value or get value from user, unless override is enabled
    if override:
        value = ""
    elif random_type:
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

    # If override is enabled, get the overridden value from the user
    if override:
        override_value = getpass.getpass("✨ Please enter the 🔏 override value (hidden): ")
    else:
        override_value = None

    try:
        # Encrypt and POST secret to the backend using phase create
        response = phase.create(key_value_pairs=[(key, value)], env_name=env_name, app_name=phase_app, path=path, override_value=override_value)

        # Check the response status code
        if response.status_code == 200:
            # Call the phase_list_secrets function to list the secrets
            phase_list_secrets(show=False, phase_app=phase_app, env_name=env_name, path=path)
        else:
            # Print an error message if the response status code indicates an error
            print(f"Error: Failed to create secret. HTTP Status Code: {response.status_code}")

    except ValueError as e:
        console.log(f"Error: {e}")
