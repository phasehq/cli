import sys
import getpass
from phase_cli.utils.phase_io import Phase
from phase_cli.cmd.secrets.list import phase_list_secrets

def phase_secrets_create(key=None, env_name=None, phase_app=None):
    """
    Creates a new secret, encrypts it, and saves it in PHASE_SECRETS_DIR.

    Args:
        key (str, optional): The key of the new secret. Defaults to None.
        env_name (str, optional): The name of the environment where the secret will be created. Defaults to None.
        phase_app (str, optional): The name of the Phase application. Defaults to None.
    """

    # Initialize the Phase class
    phase = Phase()

    # If the key is not passed as an argument, prompt user for input
    if key is None:
        key = input("🗝️  Please enter the key: ")
    key = key.upper()

    # Check if input is being piped
    if sys.stdin.isatty():
        value = getpass.getpass("✨ Please enter the value (hidden): ")
    else:
        value = sys.stdin.read().strip()

    try:
        # Encrypt and send secret to the backend using the `create` method
        response = phase.create(key_value_pairs=[(key, value)], env_name=env_name, app_name=phase_app)

        # Check the response status code
        if response.status_code == 200:
            # Call the phase_list_secrets function to list the secrets
            phase_list_secrets(show=False, env_name=env_name)
        else:
            # Print an error message if the response status code indicates an error
            print(f"Error: Failed to create secret. HTTP Status Code: {response.status_code}")

    except ValueError:
        print(f"⚠️  Warning: The environment '{env_name}' either does not exist or you do not have access to it.")
