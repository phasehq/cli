import os
import sys
import re
import keyring
import json
import shutil
import subprocess
import getpass
import questionary
from phase_cli.utils.phase_io import Phase
from phase_cli.utils.misc import render_table, get_default_user_id, sanitize_value
from phase_cli.utils.const import PHASE_ENV_CONFIG, PHASE_SECRETS_DIR, PHASE_CLOUD_API_HOST, cross_env_pattern, local_ref_pattern

# Takes Phase credentials from user and stored them securely in the system keyring
def phase_auth():
    """
    Authenticates the user with Phase, takes credentials, and stores them securely in the system keyring.
    """
    try:
        # Ask the user for the type of Phase instance they are using
        phase_instance_type = questionary.select(
            'Choose your Phase instance type:',
            choices=['☁️` Phase Cloud', '🛠️` Self Hosted']
        ).ask()

        # Set up the PHASE_API_HOST variable
        PHASE_API_HOST = None

        # If the user chooses "Self Hosted", ask for the host URL
        if phase_instance_type == '🛠️` Self Hosted':
            PHASE_API_HOST = questionary.text("Please enter your host (URL):").ask()
        else:
            PHASE_API_HOST = PHASE_CLOUD_API_HOST

        user_email = questionary.text("Please enter your email:").ask()
        pss = getpass.getpass("Please enter Phase user token (hidden): ")

        # Check if the creds are valid
        phase = Phase()
        result = phase.auth()  # Trying to authenticate using the provided pss

        if result == "Success":
            user_data = phase.init()
            user_id = user_data["user_id"]
            offline_enabled = user_data["offline_enabled"]
            wrapped_key_share = None if not offline_enabled else user_data["wrapped_key_share"]

            # Save the credentials in the Phase keyring
            keyring.set_password(f"phase-cli-user-{user_id}", "pss", pss)

            # Prepare the data to be saved in config.json
            config_data = {
                "default-user": user_id,
                "phase-users": [
                    {
                        "email": user_email,
                        "host": PHASE_API_HOST,
                        "id": user_id,
                        "wrapped_key_share": wrapped_key_share
                    }
                ]
            }

            # Save the data in PHASE_SECRETS_DIR/config.json
            os.makedirs(PHASE_SECRETS_DIR, exist_ok=True)
            with open(os.path.join(PHASE_SECRETS_DIR, 'config.json'), 'w') as f:
                json.dump(config_data, f, indent=4)
            
            print("Authentication successful. Credentials saved in the Phase keyring.")
        else:
            print("Failed to authenticate with the provided credentials.")
            
    except KeyboardInterrupt:
        # Handle the Ctrl+C event quietly
        sys.exit(0)
    except Exception as e:
        # Handle other exceptions if needed
        print(f"An error occurred: {e}")
        sys.exit(1)


# Initializes a .phase.json in the root of the dir of where the command is run
def phase_init():
    """
    Initializes the Phase application by linking the user's project to a Phase app.
    """
    # Initialize the Phase class
    phase = Phase()

    try:
        data = phase.init()
    except ValueError as err:
        print(err)
        return

    try:
        # Present a list of apps to the user and let them choose one
        app_choices = [app['name'] for app in data['apps']]
        app_choices.append('Exit')  # Add Exit option at the end

        selected_app_name = questionary.select(
            'Select an App:',
            choices=app_choices
        ).ask()

        # Check if the user selected the "Exit" option
        if selected_app_name == 'Exit':
            sys.exit(0)

        # Find the selected app's details
        selected_app_details = next(
            (app for app in data['apps'] if app['name'] == selected_app_name),
            None
        )

        # Check if selected_app_details is None (no matching app found)
        if selected_app_details is None:
            sys.exit(1)

        # Extract the default environment ID for the environment named "Development"
        default_env = next(
            (env_key for env_key in selected_app_details['environment_keys'] if env_key['environment']['name'] == 'Development'),
            None
        )

        if not default_env:
            raise ValueError("No 'Development' environment found.")

        # Save the selected app’s environment details to the .phase.json file
        phase_env = {
            "version": "1",
            "phaseApp": selected_app_name,
            "appId": selected_app_details['id'],  # Save the app id
            "defaultEnv": default_env['environment']['name'],
        }

        # Create .phase.json
        with open(PHASE_ENV_CONFIG, 'w') as f:
            json.dump(phase_env, f, indent=2)
        os.chmod(PHASE_ENV_CONFIG, 0o600)

        print("✅ Initialization completed successfully.")

    except KeyboardInterrupt:
        # Handle the Ctrl+C event quietly
        sys.exit(0)
    except Exception as e:
        # Handle other exceptions if needed
        print(e)
        sys.exit(1)


# Creates new secrets, encrypts them and saves them in PHASE_SECRETS_DIR
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
        key = input("Please enter the key: ")
    key = key.upper()
        
    value = getpass.getpass("Please enter the value (hidden): ")
    
    # Encrypt and send secret to the backend using the `create` method
    response = phase.create(key_value_pairs=[(key, value)], env_name=env_name, app_name=phase_app )
    
    # Check the response status code
    if response.status_code == 200:
        # Call the phase_list_secrets function to list the secrets
        phase_list_secrets(show=False, env_name=env_name)
    else:
        # Print an error message if the response status code indicates an error
        print(f"Error: Failed to create secret. HTTP Status Code: {response.status_code}")


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
    
    try:
        # Check if the secret with the given key exists
        key = key.upper()
        # Pass the key within a list to the get method
        secrets_data = phase.get(env_name=env_name, keys=[key], app_name=phase_app)
    except ValueError as e:
        # Key not found in the backend
        print("Secret not found...")
        return

    # Find the specific secret for the given key
    secret_data = next((secret for secret in secrets_data if secret["key"] == key), None)

    # If no matching secret found, raise an error
    if not secret_data:
        print(f"No secret found for key: {key}")
        return

    # Prompt user for the new value in a hidden manner
    new_value = getpass.getpass(f"Please enter the new value for {key} (hidden): ")

    # Call the update method of the Phase class
    response = phase.update(env_name=env_name, key=key, value=new_value, app_name=phase_app)
    
    # Check the response status code (assuming the update method returns a response with a status code)
    if response == "Success":
        print("Successfully updated the secret. ")
    else:
        print(f"Error: Failed to update secret. HTTP Status Code: {response.status_code}")
    
    # List remaining secrets (censored by default)
    phase_list_secrets(show=False, env_name=env_name)


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
        keys_to_delete = [key.upper() for key in keys_to_delete_input.split()]

    # Delete keys and get the list of keys not found
    keys_not_found = phase.delete(env_name=env_name, keys_to_delete=keys_to_delete, app_name=phase_app)

    if keys_not_found:
        print(f"Warning: The following keys were not found: {', '.join(keys_not_found)}")
    else:
        print("Successfully deleted the secrets.")

    # List remaining secrets (censored by default)
    phase_list_secrets(show=False, env_name=env_name)


def phase_secrets_env_import(env_file, env_name=None, phase_app=None):
    """
    Imports existing environment variables and secrets from a user's .env file.

    Args:
        env_file (str): Path to the .env file.
        env_name (str, optional): The name of the environment to which secrets should be saved. Defaults to None.
        phase_app (str, optional): The name of the Phase application. Defaults to None.

    Raises:
        FileNotFoundError: If the provided .env file is not found.
    """
    # Initialize the Phase class
    phase = Phase()
    
    # Parse the .env file
    secrets = []
    try:
        with open(env_file) as f:
            for line in f:
                # Ignore lines that start with a '#' or don't contain an '='
                line = line.strip()
                if line.startswith('#') or '=' not in line:
                    continue
                key, _, value = line.partition('=')
                secrets.append((key.strip().upper(), sanitize_value(value.strip())))
    
    except FileNotFoundError:
        print(f"Error: The file {env_file} was not found.")
        sys.exit(1)
    
    # Encrypt and send secrets to the backend using the `create` method
    response = phase.create(key_value_pairs=secrets, env_name=phase_app, app_name=phase_app)
    
    # Check the response status code
    if response.status_code == 200:
        print(f"Successfully imported and encrypted {len(secrets)} secrets.")
        if env_name == None:
            print("To view them please run: phase secrets list")
        else:
            print(f"To view them please run: phase secrets list --env {env_name}")
    else:
        # Print an error message if the response status code indicates an error
        print(f"Error: Failed to import secrets. HTTP Status Code: {response.status_code}")


def phase_secrets_env_export(env_name=None, phase_app=None, keys=None):
    """
    Decrypts and exports secrets to a plain text .env format based on the provided environment and keys.

    Args:
        env_name (str, optional): The name of the environment from which secrets are fetched. Defaults to None.
        phase_app (str, optional): The name of the Phase application. Defaults to None.
        keys (list, optional): List of keys for which to fetch the secrets. If None, fetches all secrets. Defaults to None.
    """
    phase = Phase()
    secrets_data = phase.get(env_name=env_name, keys=keys, app_name=phase_app)
    
    for secret in secrets_data:
        key = secret.get("key")
        value = secret.get("value")
        print(f'{key}={value}')


def phase_cli_logout(purge=False):
    if purge:
        all_user_ids = get_default_user_id(all_ids=True)
        for user_id in all_user_ids:
            keyring.delete_password(f"phase-cli-user-{user_id}", "pss")

        # Delete PHASE_SECRETS_DIR if it exists
        if os.path.exists(PHASE_SECRETS_DIR):
            shutil.rmtree(PHASE_SECRETS_DIR)
            print("Purged all local data.")
        else:
            print("No local data found to purge.")

    else:
        # For the default user
        pss = keyring.get_password("phase", "pss")
        if not pss:
            print("No configuration found. Please run 'phase auth' to set up your configuration.")
            sys.exit(1)
        keyring.delete_password("phase", "pss")
        print("Logged out successfully.")


def phase_secrets_get(key, env_name=None, phase_app=None):
    """
    Fetch and print a single secret based on a given key.
    
    :param key: The key associated with the secret to fetch.
    :param env_name: The name of the environment, if any. Defaults to None.
    """

    # Initialize the Phase class
    phase = Phase()
    
    try:
        key = key.upper()
        # Here we wrap the key in a list since the get method now expects a list of keys
        secrets_data = phase.get(env_name=env_name, keys=[key], app_name=phase_app)
    except ValueError as e:
        print("🔍 Secret not found...")
        return

    # Find the specific secret for the given key
    secret_data = next((secret for secret in secrets_data if secret["key"] == key), None)
    
    # Check that secret_data was found and is a dictionary
    if not secret_data:
        print("🔍 Secret not found...")
        return
    if not isinstance(secret_data, dict):
        raise ValueError("Unexpected format: secret data is not a dictionary")
    
    # Print the secret data in a table-like format
    render_table([secret_data], show=True)
            

def phase_list_secrets(show=False, env_name=None, phase_app=None):
    """
    Lists the secrets fetched from Phase for the specified environment.

    Args:
        show (bool, optional): Whether to show the decrypted secrets. Defaults to False.
        env_name (str, optional): The name of the environment from which secrets are fetched. Defaults to None.
        phase_app (str, optional): The name of the Phase application. Defaults to None.

    Raises:
        ValueError: If the returned secrets data from Phase is not in the expected list format.
    """
    # Initialize the Phase class
    phase = Phase()

    secrets_data = phase.get(env_name=env_name, app_name=phase_app)

    # Check that secrets_data is a list of dictionaries
    if not isinstance(secrets_data, list):
        raise ValueError("Unexpected format: secrets data is not a list")

    # Render the table
    render_table(secrets_data, show=show)

    if not show:
        print("\n🥽 To uncover the secrets, use: phase secrets list --show")



def phase_run_inject(command, env_name=None, phase_app=None):
    """
    Executes a given shell command with the environment variables set to the secrets 
    fetched from Phase for the specified environment.
    
    The function fetches the decrypted secrets, resolves any references to other secrets, 
    and then runs the specified command with the secrets injected as environment variables.
    
    Args:
        command (str): The shell command to be executed.
        env_name (str, optional): The name of the environment from which secrets are fetched. Defaults to None.
        phase_app (str, optional): The name of the Phase application. Defaults to None.
        
    Raises:
        ValueError: If there's an issue with fetching the secrets or if the data format is unexpected.
        Exception: For any subprocess-related errors.
    """
    
    # Initialize the Phase class
    phase = Phase()
    
    # Fetch the decrypted secrets using the `get` method
    try:
        secrets = phase.get(env_name=env_name, app_name=phase_app)
    except ValueError as e:
        print(f"Failed to fetch secrets: {e}")
        sys.exit(1)
    
    # Prepare the new environment variables for the command
    new_env = os.environ.copy()
    
    # Create a dictionary from the fetched secrets for easy look-up
    secrets_dict = {secret["key"]: secret["value"] for secret in secrets}
    
    # Iterate through the secrets and resolve references
    for key, value in secrets_dict.items():
        cross_env_match = re.match(cross_env_pattern, value)
        local_ref_match = re.match(local_ref_pattern, value)

        if cross_env_match:  # Cross environment reference
            ref_env, ref_key = cross_env_match.groups()
            try:
                # Wrap ref_key in a list when calling the get method
                ref_secret = phase.get(env_name=ref_env, keys=[ref_key], app_name=phase_app)[0]
                new_env[key] = ref_secret['value']
            except ValueError as e:
                print(f"Warning: Reference {ref_key} in environment {ref_env} not found for key {key}. Ignoring...")
        elif local_ref_match:  # Local environment reference
            ref_key = local_ref_match.group(1)
            new_env[key] = secrets_dict.get(ref_key, f"Warning: Local reference {ref_key} not found for key {key}. Ignoring...")
        else:
            new_env[key] = value

    # Use shell=True to allow command chaining
    subprocess.run(command, shell=True, env=new_env)
