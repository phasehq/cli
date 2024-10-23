from phase_cli.utils.phase_io import Phase
from phase_cli.cmd.secrets.list import phase_list_secrets
from rich.console import Console
from typing import List

def phase_secrets_delete(keys_to_delete: List[str] = None, env_name: str = None, phase_app: str = None, phase_app_id: str = None, path: str = None):
    """
    Deletes encrypted secrets based on key values, with optional path support.

    Args:
        keys_to_delete (list, optional): List of keys to delete. Defaults to an empty list if not provided.
        env_name (str, optional): The name of the environment from which secrets will be deleted. Defaults to None.
        phase_app (str, optional): The name of the Phase application. Defaults to None.
        path (str, optional): The path within which to delete the secrets. If specified, only deletes secrets within this path.
    """
    # Initialize the Phase class and console
    phase = Phase()
    console = Console()

    # Prompt for keys to delete if not provided
    if not keys_to_delete:
        keys_to_delete_input = input("Please enter the keys to delete (separate multiple keys with a space): ")
        keys_to_delete = keys_to_delete_input.split()

    # Convert each key to uppercase
    keys_to_delete = [key.upper() for key in keys_to_delete]

    try:
        # Delete keys within the specified path and get the list of keys not found
        keys_not_found = phase.delete(env_name=env_name, keys_to_delete=keys_to_delete, app_name=phase_app, app_id=phase_app_id, path=path)

        if keys_not_found:
            console.log(f"⚠️  Warning: The following keys were not found: {', '.join(keys_not_found)}")
        else:
            console.log("✅ Successfully deleted the secrets.")

        # Optionally, list remaining secrets to confirm deletion
        phase_list_secrets(show=False, env_name=env_name, phase_app=phase_app, phase_app_id=phase_app_id, path=path)
    
    except ValueError as e:
        console.log(f"Error: {e}")
