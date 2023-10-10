from phase_cli.utils.phase_io import Phase
from phase_cli.cmd.secrets.list import phase_list_secrets

# Deletes encrypted secrets based on key value pairs
def phase_secrets_delete(keys_to_delete=[], env_name=None, phase_app=None):
    """
    Deletes encrypted secrets based on key values.

    Args:
        keys_to_delete (list, optional): List of keys to delete. Defaults to empty list.
        env_name (str, optional): The name of the environment from which secrets will be deleted. Defaults to None.
        phase_app (str, optional): The name of the Phase application. Defaults to None.
    """
    # Initialize the Phase class
    phase = Phase()

    # If keys_to_delete is empty, request user input
    if not keys_to_delete:
        keys_to_delete_input = input("Please enter the keys to delete (separate multiple keys with a space): ")
        keys_to_delete = keys_to_delete_input.split()

    # Convert each key to uppercase
    keys_to_delete = [key.upper() for key in keys_to_delete]

    try:
        # Delete keys and get the list of keys not found
        keys_not_found = phase.delete(env_name=env_name, keys_to_delete=keys_to_delete, app_name=phase_app)

        if keys_not_found:
            print(f"⚠️  Warning: The following keys were not found: {', '.join(keys_not_found)}")
        else:
            print("Successfully deleted the secrets.")

        # List remaining secrets (censored by default)
        phase_list_secrets(show=False, env_name=env_name)
    
    except ValueError as e:
        print(e)