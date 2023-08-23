import os
import sys
import keyring
import json
import uuid
import shutil
import subprocess
import getpass
import questionary
from utils.phase_io import Phase
from utils.misc import censor_secret, render_table, get_default_user_host, get_default_user_id, phase_get_context
from utils.keyring import get_credentials
from utils.const import PHASE_ENV_CONFIG, PHASE_SECRETS_DIR, PHASE_CLOUD_API_HOST

# Takes Phase credentials from user and stored them securely in the system keyring
def phase_auth():
    try:
        # If credentials already exist, ask for confirmation to overwrite
        # default_user_id = get_default_user_id()
        # if keyring.get_password("phase", "pss"):
        #     confirmation = questionary.confirm(
        #         "You are already logged in. Do you want to switch accounts?"
        #     ).ask()
        #     if not confirmation:
        #         return

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
        phase = Phase(pss, host=PHASE_API_HOST)
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
    # Get credentials from the keyring
    pss = get_credentials()

    # Check if Phase credentials exist
    if not pss:
        print("No configuration found. Please run 'phase auth' to set up your configuration.")
        sys.exit(1)

    host = get_default_user_host()
    phase = Phase(pss, host)

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

        # Build the phaseEnvironments list
        phase_environments = [{
            "env": env_key['environment']['name'],
            "envType": env_key['environment']['env_type'],
            "id": env_key['environment']['id'],  # Use the id from the environment object
            "publicKey": env_key['identity_key'],
            "salt": env_key['wrapped_salt']
        } for env_key in selected_app_details['environment_keys']]

        # Save the selected app’s environment details to the .phase.json file
        phase_env = {
            "version": "1",
            "phaseApp": selected_app_name,
            "defaultEnv": default_env['environment']['id'],  # Use the id from the environment object
            "phaseEnvironments": phase_environments
        }

        # Create .phase.json
        with open(PHASE_ENV_CONFIG, 'w') as f:
            json.dump(phase_env, f, indent=4)
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
def phase_secrets_create(key=None, env_name=None):
    # Get credentials from the keyring
    pss = get_credentials()

    if not pss:
        print("No configuration found. Please run 'phase auth' to set up your configuration.")
        sys.exit(1)
    
    # Get context (environment ID and public key) using the optional env_name parameter
    env_id, public_key = phase_get_context(env_name)
    
    # Initialize Phase class instance
    host = get_default_user_host()
    phase = Phase(pss, host)
    
    # If the key is not passed as an argument, prompt user for input
    if key is None:
        key = input("Please enter the key: ")
        
    value = getpass.getpass("Please enter the value (hidden): ")
    
    # Encrypt and send secret to the backend using the `create` method
    response = phase.create(env_id, public_key, [(key, value)])
    
    # Check the response status code
    if response.status_code == 200:
        # Call the phase_list_secrets function to list the secrets
        phase_list_secrets(show=False, env_name=env_name)
    else:
        # Print an error message if the response status code indicates an error
        print(f"Error: Failed to create secret. HTTP Status Code: {response.status_code}")


def phase_secrets_update(key, env_name=None):
    # Get credentials from the keyring
    pss = get_credentials()

    if not pss:
        print("No configuration found. Please run 'phase auth' to set up your configuration.")
        sys.exit(1)

    # Use phase_get_context function to get environment id and public key
    environment_id, public_key = phase_get_context(env_name)

    # Fetch secrets using Phase.get
    host = get_default_user_host()
    phase = Phase(pss, host)
    
    try:
        # Check if the secret with the given key exists
        secret_data = phase.get(environment_id, key=key, public_key=public_key)
    except ValueError as e:
        # Key not found in the backend
        print("Secret not found...")
        return

    # Prompt user for the new value in a hidden manner
    new_value = getpass.getpass(f"Please enter the new value for {key} (hidden): ")

    # Call the update method of the Phase class
    response = phase.update(environment_id, public_key, key, new_value)
    
    # Check the response status code (assuming the update method returns a response with a status code)
    if response == "Success":
        print("Successfully updated the secret. ")
    else:
        print(f"Error: Failed to update secret. HTTP Status Code: {response.status_code}")
    
    # List remaining secrets (censored by default)
    phase_list_secrets(show=False, env_name=env_name)


# Deletes encrypted secrets based on key value pairs
def phase_secrets_delete(keys_to_delete=[]):
    # Get credentials from the keyring
    pss = get_credentials()

    if not pss:
        print("No configuration found. Please run 'phase auth' to set up your configuration.")
        sys.exit(1)
    
    # Get context (environment ID and public key) using the optional env_name parameter
    env_id, public_key = phase_get_context(None)
    
    # Initialize Phase class instance
    host = get_default_user_host()
    phase = Phase(pss, host)
    
    # If keys_to_delete is empty, request user input
    if not keys_to_delete:
        keys_to_delete_input = input("Please enter the keys to delete (separate multiple keys with a space): ")
        keys_to_delete = keys_to_delete_input.split()
    
    # Delete keys
    response = phase.delete(env_id, public_key, keys_to_delete)
    
    # Check the response status code
    if response.status_code == 200:
        print("Successfully deleted the secrets.")
    else:
        # Print an error message if the response status code indicates an error
        print(f"Error: Failed to delete secrets. HTTP Status Code: {response.status_code}")
    
    # List remaining secrets (censored by default)
    phase_list_secrets(show=False, env_name=env_name)



# Imports existing environment variables and secrets from users .env file based on PHASE_ENV_CONFIG context
def phase_secrets_env_import(env_file, env_name=None):
    # Get credentials from the keyring
    pss = get_credentials()

    if not pss:
        print("No configuration found. Please run 'phase auth' to set up your configuration.")
        sys.exit(1)
    
    # Get context (environment ID and public key) using the optional env_name parameter
    env_id, public_key = phase_get_context(env_name)
    
    # Initialize Phase class instance
    host = get_default_user_host()
    phase = Phase(pss, host)
    
    # Parse the .env file
    try:
        with open(env_file) as f:
            secrets = []
            for line in f:
                # Ignore lines that start with a '#' or don't contain an '='
                line = line.strip()
                if line.startswith('#') or '=' not in line:
                    continue
                key, _, value = line.partition('=')
                secrets.append((key.strip(), value.strip()))
    
    except FileNotFoundError:
        print(f"Error: The file {env_file} was not found.")
        sys.exit(1)
    
    # Encrypt and send secrets to the backend using the `create` method
    response = phase.create(env_id, public_key, secrets)
    
    # Check the response status code
    if response.status_code == 200:
        print("Successfully imported and encrypted secrets. Run phase secrets list to view them.")
    else:
        # Print an error message if the response status code indicates an error
        print(f"Error: Failed to import secrets. HTTP Status Code: {response.status_code}")



# Decrypts and exports environment variables and secrets based to a plain text .env file based on PHASE_ENV_CONFIG context
def phase_secrets_env_export(env_name=None):
    # Get credentials from the keyring
    pss = get_credentials()

    if not pss:
        print("No configuration found. Please run 'phase auth' to set up your configuration.")
        sys.exit(1)
    
    # Use phase_get_context function to get environment id and public key
    environment_id, public_key = phase_get_context(env_name)
    
    # Initialize Phase object
    host = get_default_user_host()
    phase = Phase(pss, host)
    
    # Use phase.get function to fetch the secrets for the specified environment
    secrets_data = phase.get(environment_id, public_key=public_key)
    
    # Create .env file
    with open('.env', 'w') as f:
        for secret in secrets_data:
            key = secret.get("key")
            value = secret.get("value")
            f.write(f'{key}={value}\n')
    
    print("Exported secrets to .env file.")


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



def phase_secrets_get(key, env_name=None):
    """
    Fetch and print a single secret based on a given key.
    
    :param key: The key associated with the secret to fetch.
    :param env_name: The name of the environment, if any. Defaults to None.
    """
    
    # Get credentials from the keyring
    pss = get_credentials()

    if not pss:
        print("No configuration found. Please run 'phase auth' to set up your configuration.")
        sys.exit(1)

    # Use phase_get_context function to get environment id and public key
    environment_id, public_key = phase_get_context(env_name)

    # Fetch secrets using Phase.get
    host = get_default_user_host()
    phase = Phase(pss, host)
    
    try:
        secret_data = phase.get(environment_id, key=key, public_key=public_key)
    except ValueError as e:
        print("Secret not found...")
        return
    
    # Check that secret_data is a dictionary
    if not isinstance(secret_data, dict):
        raise ValueError("Unexpected format: secret data is not a dictionary")
    
    # Print the secret data in a table-like format
    render_table([secret_data], show=True)
            

def phase_list_secrets(show=False, env_name=None):
    # Get credentials from the keyring
    pss = get_credentials()

    if not pss:
        print("No configuration found. Please run 'phase auth' to set up your configuration.")
        sys.exit(1)

    # Use phase_get_context function to get environment id and public key
    environment_id, public_key = phase_get_context(env_name)
    

    # Fetch secrets using Phase.get
    host = get_default_user_host()
    phase = Phase(pss, host)
    secrets_data = phase.get(environment_id, public_key=public_key)

    # Check that secrets_data is a list of dictionaries
    if not isinstance(secrets_data, list):
        raise ValueError("Unexpected format: secrets data is not a list")

    # Render the table
    render_table(secrets_data, show=show)

    if not show:
        print("\nTo uncover the secrets, use: phase secrets list --show")



def phase_run_inject(command, env_name=None):
    # Get credentials from the keyring
    pss = get_credentials()

    # Check if Phase credentials exist
    if not pss:
        print("No configuration found. Please run 'phase auth' to set up your configuration.")
        sys.exit(1)
    
    # Use phase_get_context function to get environment id and public key
    env_id, public_key = phase_get_context(env_name)
    
    # Initialize Phase class instance
    host = get_default_user_host()
    phase = Phase(pss, host)
    
    # Fetch the decrypted secrets using the `get` method
    try:
        secrets = phase.get(env_id, public_key)
    except ValueError as e:
        print(f"Failed to fetch secrets: {e}")
        sys.exit(1)
    
    # Prepare the new environment variables for the command
    new_env = os.environ.copy()
    for secret in secrets:
        new_env[secret["key"]] = secret["value"]

    # Use shell=True to allow command chaining
    subprocess.run(command, shell=True, env=new_env)
