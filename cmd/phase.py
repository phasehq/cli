import os
import keyring
import json
import uuid
import shutil
import subprocess
import getpass
from phase import Phase
from utils.misc import censor_secret
from utils.keyring import get_credentials
from utils.const import PHASE_ENV_CONFIG, PHASE_SECRETS_DIR

# Decrypts environment variables based on project context as defined in PHASE_ENV_CONFIG and returns them
def get_env_secrets(phApp, pss):
    phase = Phase(phApp, pss)
    env_vars = {}
    
    # Read appEnvID context from .phase.json
    if os.path.exists(PHASE_ENV_CONFIG):
        with open(PHASE_ENV_CONFIG) as f:
            data = json.load(f)
            secrets_file = os.path.join(PHASE_SECRETS_DIR, f"{data['appEnvID']}.json")
            
            # Read and decrypt local env vars
            if os.path.exists(secrets_file):
                with open(secrets_file) as f:
                    secrets = json.load(f)
                    for key, value in secrets.items():
                        env_vars[key] = phase.decrypt(value)
    
    return env_vars

# Takes Phase credentials from user and stored them securely in the system keyring
def phase_auth():
    # If credentials already exists, ask for confirmation to overwrite
    if keyring.get_password("phase", "phApp") or keyring.get_password("phase", "pss"):
        confirmation = input("You are already logged in. Do you want to switch accounts? [y/N]: ")
        if confirmation.lower() != 'y':
            print("Operation cancelled.")
            return

    phApp = input("Please enter the phApp value: ")
    pss = getpass.getpass("Please enter the pss value (hidden): ")

    keyring.set_password("phase", "phApp", phApp)
    keyring.set_password("phase", "pss", pss)

    print("Account credentials successfully saved in system keyring.")


# Initializes a .phase.json in the root of the dir of where the command is run
def phase_init():
    # Check if .phase.json already exists
    if os.path.exists(PHASE_ENV_CONFIG):
        confirmation = input("'You have already initialized your project with '.phase.json'. Do you want to delete it and start over? [y/N]: ")
        if confirmation.lower() != 'y':
            print("Operation cancelled.")
            return

    appEnvID = str(uuid.uuid4())
    data = {'appEnvID': appEnvID, 'defaultEnvironment': ''}
    
    # Create .phase.json
    with open(PHASE_ENV_CONFIG, 'w') as f:
        json.dump(data, f)
    os.chmod(PHASE_ENV_CONFIG, 0o600)
    
    # Create secrets file
    os.makedirs(PHASE_SECRETS_DIR, exist_ok=True)
    with open(os.path.join(PHASE_SECRETS_DIR, f"{appEnvID}.json"), 'w') as f:
        json.dump({}, f)
    
    print("Initialization completed successfully.")


# Creates new secrets, encrypts them and saves them in PHASE_SECRETS_DIR
def phase_secrets_create():
    # Get credentials from the keyring
    phApp, pss = get_credentials()

    # Check if Phase credentials exist
    if not phApp or not pss:
        print("No configuration found. Please run 'phase auth' to set up your configuration.")
        sys.exit(1)

    # Read appEnvID context from .phase.json
    if os.path.exists(PHASE_ENV_CONFIG):
        with open(PHASE_ENV_CONFIG) as f:
            data = json.load(f)
            secrets_file = os.path.join(PHASE_SECRETS_DIR, f"{data['appEnvID']}.json")
            
            # Read secrets file
            if os.path.exists(secrets_file):
                with open(secrets_file) as f:
                    secrets = json.load(f)
            else:
                secrets = {}
            
            phase = Phase(phApp, pss)
            
            # Take user input
            key = input("Please enter the key: ")
            value = getpass.getpass("Please enter the value (hidden): ")

            # Update secrets
            secrets[key] = phase.encrypt(value)

            # Update secrets file
            with open(secrets_file, 'w') as f:
                json.dump(secrets, f)
            
            # Print updated secrets
            phase_list_secrets(phApp, pss)
    else:
        print("Missing .phase.json file. Please run 'phase init' first.")
        sys.exit(1)


# Deletes encrypted secrets based on key value pairs
def phase_secrets_delete(keys_to_delete=[]):
    # Get credentials from the keyring
    phApp, pss = get_credentials()

    # Check if credentials exist
    if not phApp or not pss:
        print("No configuration found. Please run 'phase auth' to set up your configuration.")
        sys.exit(1)

    # Read phase.json
    if os.path.exists(PHASE_ENV_CONFIG):
        with open(PHASE_ENV_CONFIG) as f:
            data = json.load(f)
            secrets_file = os.path.join(PHASE_SECRETS_DIR, f"{data['appEnvID']}.json")
            
            # Read secrets file
            if os.path.exists(secrets_file):
                with open(secrets_file) as f:
                    secrets = json.load(f)

                # If keys_to_delete is empty, request user input
                if not keys_to_delete:
                    keys_to_delete = input("Please enter the keys to delete (separate multiple keys with a space): ").split()

                # Delete keys
                for key in keys_to_delete:
                    if key in secrets:
                        del secrets[key]
                        print(f"Deleted key: {key}")
                    else:
                        print(f"Key not found: {key}")
                
                # Update secrets file
                with open(secrets_file, 'w') as f:
                    json.dump(secrets, f)
            
                # Print updated secrets
                phase_list_secrets(phApp, pss)
    else:
        print("Missing phase.json file. Please run 'phase init' first.")
        sys.exit(1)


# Imports existing environment variables and secrets from users .env file based on PHASE_ENV_CONFIG context
def phase_secrets_env_import(env_file):
    # Get credentials from the keyring
    phApp, pss = get_credentials()

    # Check if credentials exist
    if not phApp or not pss:
        print("No configuration found. Please run 'phase auth' to set up your configuration.")
        sys.exit(1)

    # Read phase.json
    if os.path.exists(PHASE_ENV_CONFIG):
        with open(PHASE_ENV_CONFIG) as f:
            data = json.load(f)
            secrets_file = os.path.join(PHASE_SECRETS_DIR, f"{data['appEnvID']}.json")
            
            # Read secrets file
            if os.path.exists(secrets_file):
                with open(secrets_file) as f:
                    secrets = json.load(f)
            else:
                secrets = {}
            
            phase = Phase(phApp, pss)
            
            # Read .env file
            with open(env_file) as f:
                for line in f:
                    # Ignore lines that start with a '#' or don't contain an '='
                    line = line.strip()
                    if line.startswith('#') or '=' not in line:
                        continue
                    
                    # Split the line into a key and a value, removing any comments
                    key, _, rest = line.partition('=')
                    value, _, _ = rest.partition('#')

                    # Update secrets
                    secrets[key.strip()] = phase.encrypt(value.strip())

            # Update secrets file
            with open(secrets_file, 'w') as f:
                json.dump(secrets, f)
            
            # Print updated secrets
            phase_list_secrets(phApp, pss)
    else:
        print("Missing phase.json file. Please run 'phase init' first.")
        sys.exit(1)


# Decrypts and exports environment variables and secrets based to a plain text .env file based on PHASE_ENV_CONFIG context
def phase_secrets_env_export():
    # Get credentials from the keyring
    phApp, pss = get_credentials()

    # Check if credentials exist
    if not phApp or not pss:
        print("No configuration found. Please run 'phase auth' to set up your configuration.")
        sys.exit(1)

    # Read phase.json
    if os.path.exists(PHASE_ENV_CONFIG):
        with open(PHASE_ENV_CONFIG) as f:
            data = json.load(f)
            secrets_file = os.path.join(PHASE_SECRETS_DIR, f"{data['appEnvID']}.json")
            
            # Read secrets file
            if os.path.exists(secrets_file):
                with open(secrets_file) as f:
                    secrets = json.load(f)
            
                phase = Phase(phApp, pss)
                
                # Create .env file
                with open('.env', 'w') as f:
                    for key, value in secrets.items():
                        f.write(f'{key}={phase.decrypt(value)}\n')
                
                print("Exported secrets to .env file.")
    else:
        print("Missing phase.json file. Please run 'phase init' first.")
        sys.exit(1)


def phase_cli_logout(purge=False):
    phApp = keyring.get_password("phase", "phApp")
    pss = keyring.get_password("phase", "pss")

    if not phApp and not pss:
        print("No account found. Please log in using 'phase auth'.")
        return

    keyring.delete_password("phase", "phApp")
    keyring.delete_password("phase", "pss")

    if purge:
        # Delete PHASE_SECRETS_DIR if it exists
        if os.path.exists(PHASE_SECRETS_DIR):
            shutil.rmtree(PHASE_SECRETS_DIR)
            print("Purged all local data.")
        else:
            print("No local data found to purge.")

    print("Logged out successfully.")


def phase_list_secrets(phApp, pss, show=False):
    # Read phase.json
    if os.path.exists(PHASE_ENV_CONFIG):
        with open(PHASE_ENV_CONFIG) as f:
            data = json.load(f)
            secrets_file = os.path.join(PHASE_SECRETS_DIR, f"{data['appEnvID']}.json")
            
            # Read secrets file
            if os.path.exists(secrets_file):
                with open(secrets_file) as f:
                    secrets = json.load(f)
                
                # Initialize Phase with credentials
                phase = Phase(phApp, pss)

                # Print header
                print(f'{"Key":<30} | {"Value":<60}')

                # Print separator
                print('-' * 95)

                # Print key value pairs
                for key, value in secrets.items():
                    decrypted_value = phase.decrypt(value)
                    print(f'{key:<30} | {decrypted_value if show else censor_secret(decrypted_value):<60}')

                # Print instructions to uncover the secrets
                if not show:
                    print("\nTo uncover the secrets, use: phase secrets list --show")
    else:
        print("Missing phase.json file. Please run 'phase init' first.")
        sys.exit(1)

def phase_run_inject(command):
    # Add environment variables to current environment
    phApp, pss = get_credentials()
    if not phApp or not pss:
        print("No configuration found. Please run 'phase auth' to log in.")
        sys.exit(1)
    env_vars = get_env_secrets(phApp, pss)
    new_env = os.environ.copy()
    new_env.update(env_vars)

    # Use shell=True to allow command chaining
    subprocess.run(command, shell=True, env=new_env)