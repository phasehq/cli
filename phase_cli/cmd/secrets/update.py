import sys
import getpass
from phase_cli.utils.phase_io import Phase
from phase_cli.cmd.secrets.list import phase_list_secrets

def phase_secrets_update(key, env_name=None, phase_app=None):
    """
    Updates a secret with a new value.

    Args:
        key (str): The key of the secret to update.
        env_name (str, optional): The name of the environment in which the secret is located. Defaults to None.
        phase_app (str, optional): The name of the Phase application. Defaults to None.
    """
    # Initialize the Phase class
    phase = Phase()
    
    # Convert the key to uppercase
    key = key.upper()

    try:
        # Pass the key within a list to the get method
        secrets_data = phase.get(env_name=env_name, keys=[key], app_name=phase_app)

        # Find the specific secret for the given key
        secret_data = next((secret for secret in secrets_data if secret["key"] == key), None)

        # If no matching secret found, raise an error
        if not secret_data:
            print(f"No secret found for key: {key}")
            return
        
    except ValueError as e:
        print(e)

    # Check if input is being piped
    if sys.stdin.isatty():
        new_value = getpass.getpass(f"Please enter the new value for {key} (hidden): ")
    else:
        new_value = sys.stdin.read().strip()

    try:
        # Call the update method of the Phase class
        response = phase.update(env_name=env_name, key=key, value=new_value, app_name=phase_app)
        
        # Check the response status code (assuming the update method returns a response with a status code)
        if response == "Success":
            print("Successfully updated the secret. ")
        else:
            print(f"Error: Failed to update secret. HTTP Status Code: {response.status_code}")

        # List remaining secrets (censored by default)
        phase_list_secrets(show=False, env_name=env_name)
    
    except ValueError:
        print(f"⚠️  Error occurred while updating the secret.")
