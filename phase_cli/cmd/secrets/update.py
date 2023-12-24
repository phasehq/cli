import sys
import getpass
from phase_cli.utils.phase_io import Phase
from phase_cli.cmd.secrets.list import phase_list_secrets
from phase_cli.utils.crypto import generate_random_secret
from rich.console import Console

def phase_secrets_update(key, env_name=None, phase_app=None, random_type=None, random_length=None):
    """
    Updates a secret with a new value or a randomly generated value.

    Args:
        key (str): The key of the secret to update.
        env_name (str, optional): The name of the environment in which the secret is located. Defaults to None.
        phase_app (str, optional): The name of the Phase application. Defaults to None.
        random_type (str, optional): The type of random secret to generate (e.g., 'hex', 'alphanumeric'). Defaults to None.
        random_length (int, optional): The length of the random secret. Defaults to 32.
    """
    # Initialize the Phase class
    phase = Phase()
    console = Console()
    
    # Convert the key to uppercase
    key = key.upper()

    # Check if the secret exists
    try:
        secrets_data = phase.get(env_name=env_name, keys=[key], app_name=phase_app)
        secret_data = next((secret for secret in secrets_data if secret["key"] == key), None)
        if not secret_data:
            print(f"🔍 No secret found for key: {key}")
            return
    except ValueError as e:
        console.log(f"Error: {e}")
        return

    # Generate a random value or get value from user
    if random_type:
        # Check if length is specified for key128 or key256
        if random_type in ['key128', 'key256'] and random_length != 32:
            print("⚠️  Warning: The length argument is ignored for 'key128' and 'key256'. Using default lengths.")

        try:
            new_value = generate_random_secret(random_type, random_length)
        except ValueError as e:
            console.log(f"Error: {e}")
            return
    else:
        # Check if input is being piped
        if sys.stdin.isatty():
            new_value = getpass.getpass(f"Please enter the new value for {key} (hidden): ")
        else:
            new_value = sys.stdin.read().strip()

    # Update the secret
    try:
        response = phase.update(env_name=env_name, key=key, value=new_value, app_name=phase_app)
        if response == "Success":
            print("Successfully updated the secret.")
        else:
            print(f"Error: Failed to update secret. HTTP Status Code: {response.status_code}")
        phase_list_secrets(show=False, env_name=env_name)
    except ValueError:
        print(f"⚠️  Error occurred while updating the secret.")
