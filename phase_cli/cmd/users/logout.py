import json
import os
import sys
import shutil
import keyring
from phase_cli.utils.const import PHASE_SECRETS_DIR, CONFIG_FILE
from phase_cli.utils.misc import get_default_account_id
from rich.console import Console

console = Console(stderr=True)
def save_config(config_data):
    """Saves the updated configuration data to the config file."""
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config_data, f, indent=4)

def phase_cli_logout(purge=False):
    """Log out from the phase CLI. Deletes credentials from keyring and optionally purges all local data."""
    config_file_path = CONFIG_FILE

    if purge:
        try:
            all_account_ids = get_default_account_id(all_ids=True)
            for account_id in all_account_ids:
                keyring.delete_password(f"phase-cli-user-{account_id}", "pss")

            # Delete PHASE_SECRETS_DIR if it exists
            if os.path.exists(PHASE_SECRETS_DIR):
                shutil.rmtree(PHASE_SECRETS_DIR)
                console.print("Logged out and purged all local data.")
            else:
                console.print("No local data found to purge.")
        except ValueError as e:
            console.log(f"Error: {e}")
            sys.exit(1)
    else:
        # Load the existing config to update it
        if not os.path.exists(config_file_path):
            console.log("Error: No configuration found. Please run 'phase auth' to set up your configuration.")
            sys.exit(1)

        with open(config_file_path, 'r') as f:
            config_data = json.load(f)

        # Identify the default account and remove their credentials
        default_account_id = get_default_account_id()
        if default_account_id:
            keyring.delete_password(f"phase-cli-user-{default_account_id}", "pss")
            # Remove the default account from the config
            config_data['phase-users'] = [user for user in config_data['phase-users'] if user['id'] != default_account_id]
            # If there are no users left, remove the default user ID as well
            if not config_data['phase-users']:
                config_data.pop('default-user', None)
            else:
                # Update the default user to the next available user, if any
                config_data['default-user'] = config_data['phase-users'][0]['id']

            save_config(config_data)
            console.print("Logged out successfully.")
        else:
            console.log("Error: No default user in configuration found. Please run 'phase auth' to set up your configuration.")