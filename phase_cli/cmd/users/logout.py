import json
import os
import sys
import shutil
import keyring
from phase_cli.utils.const import PHASE_SECRETS_DIR, CONFIG_FILE
from phase_cli.utils.misc import get_default_user_id

def save_config(config_data):
    """Saves the updated configuration data to the config file."""
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config_data, f, indent=4)

def phase_cli_logout(purge=False):
    """Log out from the phase CLI. Deletes credentials from keyring and optionally purges all local data."""
    config_file_path = CONFIG_FILE

    if purge:
        try:
            all_user_ids = get_default_user_id(all_ids=True)
            for user_id in all_user_ids:
                keyring.delete_password(f"phase-cli-user-{user_id}", "pss")

            # Delete PHASE_SECRETS_DIR if it exists
            if os.path.exists(PHASE_SECRETS_DIR):
                shutil.rmtree(PHASE_SECRETS_DIR)
                print("Logged out and purged all local data.")
            else:
                print("No local data found to purge.")
        except ValueError as e:
            print(e)
            sys.exit(1)
    else:
        # Load the existing config to update it
        if not os.path.exists(config_file_path):
            print("No configuration found. Please run 'phase auth' to set up your configuration.")
            sys.exit(1)

        with open(config_file_path, 'r') as f:
            config_data = json.load(f)

        # Identify the default user and remove their credentials
        default_user_id = get_default_user_id()
        if default_user_id:
            keyring.delete_password(f"phase-cli-user-{default_user_id}", "pss")
            # Remove the default user from the config
            config_data['phase-users'] = [user for user in config_data['phase-users'] if user['id'] != default_user_id]
            # If there are no users left, remove the default user ID as well
            if not config_data['phase-users']:
                config_data.pop('default-user', None)
            else:
                # Update the default user to the next available user, if any
                config_data['default-user'] = config_data['phase-users'][0]['id']

            save_config(config_data)
            print("Logged out successfully.")
        else:
            print("No default user in configuration found. Please run 'phase auth' to set up your configuration.")