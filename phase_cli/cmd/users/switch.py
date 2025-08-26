import json
import os
import sys
from questionary import select, Separator
from phase_cli.utils.const import CONFIG_FILE

def load_config():
    if not os.path.exists(CONFIG_FILE):
        print("No configuration found. Please run 'phase auth' to set up your configuration.")
        return None
    try:
        with open(CONFIG_FILE, 'r') as f:
            return json.load(f)
    except json.JSONDecodeError:
        print("Error reading the config file. The file may be corrupted or not in the expected format.")
        sys.exit(1)

def save_config(config_data):
    try:
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config_data, f, indent=4)
    except Exception as e:
        print(f"Error saving configuration: {e}")
        sys.exit(1)

def switch_user():
    config_data = load_config()
    if not config_data:
        sys.exit(1)

    # Prepare user choices, including a visual separator as a title.
    # Also, create a mapping for the partial UUID to the full UUID.
    uuid_mapping = {}
    user_choices = [Separator("🏢 Organization, ✉️\u200A Email, ☁️\u200A Phase Host, 🆔 Account ID")] + [
        f"{user.get('organization_name', 'N/A') if user.get('organization_name') else 'N/A'}, {user.get('email', 'Service Account')}, {user['host']}, {user['id'][:8]}"
        for user in config_data['phase-users']
    ]
    
    for user in config_data['phase-users']:
        partial_uuid = user['id'][:8]
        uuid_mapping[partial_uuid] = user['id']

    try:
        while True:
            selected = select(
                "Choose an account to switch to:",
                choices=user_choices
            ).ask()

            # Break if selection is cancelled (Ctrl+C or escape)
            if selected is None:
                break

            # Extract the UUID part from the selection.
            uuid_selected = selected.split(", ")[-1]

            # Use the full UUID from the mapping to identify and switch to the selected user.
            full_uuid = uuid_mapping.get(uuid_selected, None)
            if full_uuid:
                config_data['default-user'] = full_uuid
                save_config(config_data)
                print(f"Switched to account 🙋: {selected}")
                break
            else:
                print("Account switch failed.")
                sys.exit(1)
    except KeyboardInterrupt:
        sys.exit(0)
    except Exception as e:
        print(f"Error switching account: {e}")
        sys.exit(1)
