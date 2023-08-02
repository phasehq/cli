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
from argparse import RawTextHelpFormatter
from phase import Phase

__version__ = "0.1.0b"

# Define constants
PHASE_ENV_CONFIG = '.phase.json'
PHASE_CONFIG_DIR = os.path.expanduser('~/.phase/secrets')

def printPhaseCliVersion():
    print(f"Version: {__version__}")

def printPhaseCliVersionOnly():
    print(f"{__version__}")

def getEnvSecrets(phApp, pss):
    phase = Phase(phApp, pss)
    env_vars = {}
    
    # Read appEnvID context from .phase.json
    if os.path.exists(PHASE_ENV_CONFIG):
        with open(PHASE_ENV_CONFIG) as f:
            data = json.load(f)
            secrets_file = os.path.join(PHASE_CONFIG_DIR, f"{data['appEnvID']}.json")
            
            # Read and decrypt local env vars
            if os.path.exists(secrets_file):
                with open(secrets_file) as f:
                    secrets = json.load(f)
                    for key, value in secrets.items():
                        env_vars[key] = phase.decrypt(value)
    
    return env_vars

def phaseAuth():
    # If configuration already exists, ask for confirmation to overwrite
    if keyring.get_password("phase", "phApp") or keyring.get_password("phase", "pss"):
        confirmation = input("Configuration already exists. Do you want to overwrite it? [y/N]: ")
        if confirmation.lower() != 'y':
            print("Operation cancelled.")
            return

    phApp = input("Please enter the phApp value: ")
    pss = getpass.getpass("Please enter the pss value (hidden): ")

    keyring.set_password("phase", "phApp", phApp)
    keyring.set_password("phase", "pss", pss)

    print("Configuration saved successfully.")

def phaseInit():
    appEnvID = str(uuid.uuid4())
    data = {'appEnvID': appEnvID, 'defaultEnvironment': ''}
    
    # Create phase.json
    with open(PHASE_ENV_CONFIG, 'w') as f:
        json.dump(data, f)
    os.chmod(PHASE_ENV_CONFIG, 0o600)
    
    # Create secrets file
    os.makedirs(PHASE_CONFIG_DIR, exist_ok=True)
    with open(os.path.join(PHASE_CONFIG_DIR, f"{appEnvID}.json"), 'w') as f:
        json.dump({}, f)
    
    print("Initialization completed successfully.")

def phaseSecretsCreate():
    # Get credentials from the keyring
    phApp, pss = get_credentials()

    # Check if Phase credentials exist
    if not phApp or not pss:
        print("No configuration found. Please run 'phase-cli auth' to set up your configuration.")
        sys.exit(1)

    # Read appEnvID context from .phase.json
    if os.path.exists(PHASE_ENV_CONFIG):
        with open(PHASE_ENV_CONFIG) as f:
            data = json.load(f)
            secrets_file = os.path.join(PHASE_CONFIG_DIR, f"{data['appEnvID']}.json")
            
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
            phaseListSecrets(phApp, pss)
    else:
        print("Missing phase.json file. Please run 'phase-cli init' first.")
        sys.exit(1)

def phaseSecretsDelete(keys_to_delete=[]):
    # Get credentials from the keyring
    phApp, pss = get_credentials()

    # Check if credentials exist
    if not phApp or not pss:
        print("No configuration found. Please run 'phase-cli auth' to set up your configuration.")
        sys.exit(1)

    # Read phase.json
    if os.path.exists(PHASE_ENV_CONFIG):
        with open(PHASE_ENV_CONFIG) as f:
            data = json.load(f)
            secrets_file = os.path.join(PHASE_CONFIG_DIR, f"{data['appEnvID']}.json")
            
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
                phaseListSecrets(phApp, pss)
    else:
        print("Missing phase.json file. Please run 'phase-cli init' first.")
        sys.exit(1)

def phaseSecretsEnvImport(env_file):
    # Get credentials from the keyring
    phApp, pss = get_credentials()

    # Check if credentials exist
    if not phApp or not pss:
        print("No configuration found. Please run 'phase-cli auth' to set up your configuration.")
        sys.exit(1)

    # Read phase.json
    if os.path.exists(PHASE_ENV_CONFIG):
        with open(PHASE_ENV_CONFIG) as f:
            data = json.load(f)
            secrets_file = os.path.join(PHASE_CONFIG_DIR, f"{data['appEnvID']}.json")
            
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
            phaseListSecrets(phApp, pss)
    else:
        print("Missing phase.json file. Please run 'phase-cli init' first.")
        sys.exit(1)

def phaseSecretsEnvExport():
    # Get credentials from the keyring
    phApp, pss = get_credentials()

    # Check if credentials exist
    if not phApp or not pss:
        print("No configuration found. Please run 'phase-cli auth' to set up your configuration.")
        sys.exit(1)

    # Read phase.json
    if os.path.exists(PHASE_ENV_CONFIG):
        with open(PHASE_ENV_CONFIG) as f:
            data = json.load(f)
            secrets_file = os.path.join(PHASE_CONFIG_DIR, f"{data['appEnvID']}.json")
            
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
        print("Missing phase.json file. Please run 'phase-cli init' first.")
        sys.exit(1)

def phaseCliLogout():
    keyring.delete_password("phase", "phApp")
    keyring.delete_password("phase", "pss")
    print("Logged out successfully.")

def censorSecret(secret):
    if len(secret) <= 6:
        return '*' * len(secret)
    return secret[:3] + '*' * (len(secret) - 6) + secret[-3:]

def phaseListSecrets(phApp, pss, show=False):
    # Read phase.json
    if os.path.exists(PHASE_ENV_CONFIG):
        with open(PHASE_ENV_CONFIG) as f:
            data = json.load(f)
            secrets_file = os.path.join(PHASE_CONFIG_DIR, f"{data['appEnvID']}.json")
            
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
                    print(f'{key:<30} | {decrypted_value if show else censorSecret(decrypted_value):<60}')

                # Print instructions to uncover the secrets
                if not show:
                    print("\nTo uncover the secrets, use: phase-cli secrets list --show")
    else:
        print("Missing phase.json file. Please run 'phase-cli init' first.")
        sys.exit(1)

def phaseRunInject(command, env_vars):
    # Add environment variables to current environment
    new_env = os.environ.copy()
    new_env.update(env_vars)

    # Use shell=True to allow command chaining
    subprocess.run(command, shell=True, env=new_env)

def get_credentials():
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

def phaseOpenWeb():
    url = os.getenv('PHASE_SERVICE_ENDPOINT', 'https://console.phase.dev')
    webbrowser.open(url)

def showKeyringInfo():
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

        #parser = argparse.ArgumentParser(prog='phase-cli', description=phaseASCii, formatter_class=RawTextHelpFormatter)
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

        # Web command
        web_parser = subparsers.add_parser('web', help='Open the Phase Console in the default web browser')

        # Keyring command
        keyring_parser = subparsers.add_parser('keyring', help='Display information about the phase-cli keyring')

        args = parser.parse_args()

        phApp, pss = get_credentials()
        env_vars = getEnvSecrets(phApp, pss)

        if args.command == 'auth':
            phaseAuth()
        elif args.command == 'init':
            phaseInit()
        elif args.command == 'run':
            command = ' '.join(args.run_command)
            phaseRunInject(command, env_vars)
        elif args.command == 'logout':
            phaseCliLogout()
        elif args.command == 'web':
            phaseOpenWeb()
        elif args.command == 'keyring':
            showKeyringInfo()
        elif args.command == 'secrets':
            if args.secrets_command == 'list':
                phaseListSecrets(phApp, pss, args.show)  # Pass phApp and pss
            elif args.secrets_command == 'create':
                phaseSecretsCreate()  # Do not pass args.env
            elif args.secrets_command == 'delete':
                phaseSecretsDelete(args.keys)  # Ensure your function can handle a list of keys
            elif args.secrets_command == 'import':
                phaseSecretsEnvImport(args.env_file)  # Pass only args.env_file
            elif args.secrets_command == 'export':
                phaseSecretsEnvExport()
        else:
            print("Unknown command: " + ' '.join(args.command))
            parser.print_help()
            sys.exit(1)
    except KeyboardInterrupt:
        print("\nStopping Phase.")
        sys.exit(0)
