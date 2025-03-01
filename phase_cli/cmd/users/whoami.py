import json
import sys
from phase_cli.utils.const import CONFIG_FILE


def phase_users_whoami():
    """
    Print details of the default user.
    """
    try:
        # Load the config file
        with open(CONFIG_FILE, 'r') as f:
            config_data = json.load(f)

        # Extract the default user ID
        default_user_id = config_data.get("default-user")

        if not default_user_id:
            print("No default user set.")
            sys.exit(1)

        # Find the user details matching the default user ID
        default_user = next((user for user in config_data["phase-users"] if user["id"] == default_user_id), None)
        
        if not default_user:
            print("Default user not found in the users list.")
            sys.exit(1)

        # Print the default user details
        print(f"✉️\u200A Email: {default_user['email']}")
        print(f"🙋 User ID: {default_user['id']}")
        print(f"🏢 Organization: {default_user['organization_name']}")
        print(f"☁️\u200A Host: {default_user['host']}")

    except FileNotFoundError:
        print(f"Config file not found at {CONFIG_FILE}.")
        sys.exit(1)
    except json.JSONDecodeError:
        print("Error reading the config file. The file may be corrupted or not in the expected format.")
        sys.exit(1)
