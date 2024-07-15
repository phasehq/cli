import sys
import getpass
from phase_cli.utils.phase_io import Phase
from phase_cli.cmd.secrets.list import phase_list_secrets
from phase_cli.utils.crypto import generate_random_secret
from rich.console import Console

def phase_secrets_update(key, env_name=None, phase_app=None, random_type=None, random_length=None, source_path='', destination_path=None, override=False, toggle_override=False):
    """
    Updates a secret with a new value or a randomly generated value, with optional source and destination path support.

    Args:
        key (str): The key of the secret to update.
        env_name (str, optional): The name of the environment in which the secret is located. Defaults to None.
        phase_app (str, optional): The name of the Phase application. Defaults to None.
        random_type (str, optional): The type of random secret to generate (e.g., 'hex', 'alphanumeric'). Defaults to None.
        random_length (int, optional): The length of the random secret. Defaults to 32.
        source_path (str, optional): The current path of the secret. Defaults to root path '/'.
        destination_path (str, optional): The new path for the secret, if changing its location. If not provided, the path is not updated.
        override (bool, optional): Whether to update an overridden secret value. Defaults to False.
        toggle_override (bool, optional): Whether to toggle the override state between active and inactive. Defaults to False.
    """
    # Initialize the Phase class
    phase = Phase()
    console = Console()
    
    # If the key is not passed as an argument, prompt user for input
    if key is None:
        key = input("🗝️\u200A Please enter the key: ")

    # Replace spaces in the key with underscores
    key = key.replace(' ', '_').upper()

    # Check if toggle_override is provided, if so, do not prompt for a new value
    if toggle_override:
        new_value = None
    # Generate a random value or get value from user, unless override is enabled
    elif random_type:
        # Check if length is specified for key128 or key256
        if random_type in ['key128', 'key256'] and random_length != 32:
            print("⚠️  Warning: The length argument is ignored for 'key128' and 'key256'. Using default lengths.")

        try:
            new_value = generate_random_secret(random_type, random_length)
        except ValueError as e:
            console.log(f"Error: {e}")
            return
    elif not override:
        if sys.stdin.isatty():
            new_value = getpass.getpass(f"✨ Please enter the new value for {key} (hidden): ")
        else:
            new_value = sys.stdin.read().strip()
    else:
        new_value = getpass.getpass(f"✨ Please enter the new 🔏 override value for {key} (hidden): ")

    # Update the secret with optional source and destination path support
    try:
        response = phase.update(
            env_name=env_name, 
            key=key, 
            value=new_value, 
            app_name=phase_app, 
            source_path=source_path, 
            destination_path=destination_path, 
            override=override, 
            toggle_override=toggle_override
        )
        if response == "Success":
            print("✅ Successfully updated the secret.")
            # Optionally, list secrets after update to confirm the change
            phase_list_secrets(show=False, phase_app=phase_app, env_name=env_name, path=destination_path or source_path)
        else:
            print(f"Error: 🗿 Failed to update secret. {response}")
    except ValueError as e:
        console.log(f"⚠️  Error occurred while updating the secret: {e}")