import os
import json
import uuid
import subprocess
import sys
import getpass
import keyring
import datetime
import webbrowser
import argparse
import shutil
from argparse import RawTextHelpFormatter
from phase import Phase

__version__ = "0.2.2b"

# Define paths to Phase configs
PHASE_ENV_CONFIG = '.phase.json' # Holds project and environment contexts in users repo, unique to each application.
PHASE_SECRETS_DIR = os.path.expanduser('~/.phase/secrets') # Holds local encrypted caches of secrets and environment variables, common to all projects.

def print_phase_cli_version():
    print(f"Version: {__version__}")

def print_phase_cli_version_only():
    print(f"{__version__}")

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


def censor_secret(secret):
    if len(secret) <= 6:
        return '*' * len(secret)
    return secret[:3] + '*' * (len(secret) - 6) + secret[-3:]

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
    if not phApp or not pss:
        print("No configuration found. Please run 'phase auth' to log in.")
        sys.exit(1)
    env_vars = get_env_secrets(phApp, pss)
    new_env = os.environ.copy()
    new_env.update(env_vars)

    # Use shell=True to allow command chaining
    subprocess.run(command, shell=True, env=new_env)

def get_credentials():
    # Use environment variables if available
    phApp = os.getenv("PHASE_APP_ID")
    pss = os.getenv("PHASE_APP_SECRET")

    # If environment variables are not available, use the keyring
    if not phApp or not pss:
        try:
            phApp = keyring.get_password("phase", "phApp")
            pss = keyring.get_password("phase", "pss")
            return phApp, pss
        except keyring.errors.KeyringLocked:
            password = getpass.getpass("Please enter your keyring password: ")
            keyring.get_keyring().unlock(password)
            phApp = keyring.get_password("phase", "phApp")
            pss = keyring.get_password("phase", "pss")
            return phApp, pss
        except keyring.errors.KeyringError:
            print("System keyring is not available. Please set the PHASE_APP_ID and PHASE_APP_SECRET environment variables.")
            return None, None
    else:
        return phApp, pss

def phase_open_web():
    url = os.getenv('PHASE_SERVICE_ENDPOINT', 'https://console.phase.dev')
    webbrowser.open(url)

def show_keyring_info():
    kr = keyring.get_keyring()
    print(f"Current keyring backend: {kr.__class__.__name__}")
    print("Supported keyring backends:")
    for backend in keyring.backend.get_all_keyring():
        print(f"- {backend.__class__.__name__}")

phaseASCii = f"""                
        :S@tX88%%t.                   
        ;X;%;@%8X@%;.  Phase-cli               
      ;Xt%;S8:;;t%S    Encrypt the signal, store the noise.               
      ;SXStS@.;t8@: ;. © {datetime.datetime.now().year} Phase Security Inc.               
    ;@:t;S8  ;@.%.;8:  https://phase.dev               
    :X:S%88    S.88t:. https://github.com/phasehq/console                
  :X:%%88     :S:t.t8t                              
.@8X888@88888888X8.%8X8888888X8.S88: 
                ;t;X ;X;    ;tXS:%X;
                :@:8@X..   tXXS%S8    
                ...X:@8S ..X%88X:;     
                  ..@:X88:8Xt8:.       
                    .;%88@S8:XS                       
    """

class HelpfulParser(argparse.ArgumentParser):
    def error(self, message):
        self.print_help()
        sys.exit(2)

if __name__ == '__main__':

    try:
        parser = HelpfulParser(prog='phase-cli', description=phaseASCii, formatter_class=RawTextHelpFormatter)

        parser.add_argument('--version', '-v', action='version', version=__version__)
        subparsers = parser.add_subparsers(dest='command', required=True)

        # Auth command
        auth_parser = subparsers.add_parser('auth', help='Authenticate with Phase')

        # Init command
        init_parser = subparsers.add_parser('init', help='Link your local repo to a Phase app environment')

        # Run command
        run_parser = subparsers.add_parser('run', help='Automatically run and inject environment variables to your application')
        run_parser.add_argument('run_command', nargs=argparse.REMAINDER, help='Command to be run')

        # Secrets command
        secrets_parser = subparsers.add_parser('secrets', help='Manage your secrets')
        secrets_subparsers = secrets_parser.add_subparsers(dest='secrets_command', required=True)

        # Secrets list command
        secrets_list_parser = secrets_subparsers.add_parser('list', help='List all the secrets')
        secrets_list_parser.add_argument('--show', action='store_true', help='Show uncensored secrets')

        # Secrets create command
        secrets_create_parser = secrets_subparsers.add_parser('create', help='Create a new secret')
        secrets_create_parser.add_argument('--env', type=str, help='Import secrets from a .env file')

        # Secrets delete command
        secrets_delete_parser = secrets_subparsers.add_parser('delete', help='Delete a secret')
        secrets_delete_parser.add_argument('keys', nargs='*', help='Keys to be deleted')

        # Secrets import command
        secrets_import_parser = secrets_subparsers.add_parser('import', help='Import secrets from a .env file')
        secrets_import_parser.add_argument('env_file', type=str, help='The .env file to import')

        # Secrets export command
        secrets_export_parser = secrets_subparsers.add_parser('export', help='Export secrets to a .env file')

        # Logout command
        logout_parser = subparsers.add_parser('logout', help='Logout from phase-cli and delete local credentials')
        logout_parser.add_argument('--purge', action='store_true', help='Purge all local data')

        # Web command
        web_parser = subparsers.add_parser('web', help='Open the Phase Console in the default web browser')

        # Keyring command
        keyring_parser = subparsers.add_parser('keyring', help='Display information about the phase keyring')

        args = parser.parse_args()

        if args.command == 'auth':
            phase_auth()
            sys.exit(0)

        phApp, pss = get_credentials()
        if not phApp or not pss:
            print("No accounts found. Please run 'phase auth' or supply PHASE_APP_ID & PHASE_APP_SECRET")
            sys.exit(1)

        if args.command == 'init':
            phase_init()
        elif args.command == 'run':
            command = ' '.join(args.run_command)
            phase_run_inject(command)
        elif args.command == 'logout':
            phase_cli_logout(args.purge)
        elif args.command == 'web':
            phase_open_web()
        elif args.command == 'keyring':
            show_keyring_info()
        elif args.command == 'secrets':
            if args.secrets_command == 'list':
                phase_list_secrets(phApp, pss, args.show)  
            elif args.secrets_command == 'create':
                phase_secrets_create() 
            elif args.secrets_command == 'delete':
                phase_secrets_delete(args.keys)  
            elif args.secrets_command == 'import':
                phase_secrets_env_import(args.env_file)
            elif args.secrets_command == 'export':
                phase_secrets_env_export()
        else:
            print("Unknown command: " + ' '.join(args.command))
            parser.print_help()
            sys.exit(1)
    except KeyboardInterrupt:
        print("\nStopping Phase.")
        sys.exit(0)