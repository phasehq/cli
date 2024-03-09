import json
import os
from questionary import select, Separator
from phase_cli.utils.const import CONFIG_FILE

def load_config():
    if not os.path.exists(CONFIG_FILE):
        print("No configuration found. Please run 'phase auth' to set up your configuration.")
        return None
    with open(CONFIG_FILE, 'r') as f:
        return json.load(f)

def save_config(config_data):
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config_data, f, indent=4)

def switch_user():
    config_data = load_config()
    if not config_data:
        return

    # Prepare user choices, including a visual separator as a title.
    user_choices = [Separator("✉️\u200A Email - 🏢 Organization - 🌐 Phase Host")] + [
        f"{user['email']}, {user.get('organization_name', 'N/A')}, {user['host']}"
        for user in config_data['phase-users']
    ]

    try:
        while True:
            selected = select(
                "Choose a user to switch to:",
                choices=user_choices
            ).ask()

            # Break if selection is cancelled (Ctrl+C or escape)
            if selected is None:
                break


            email_selected = selected.split(", ")[0]

            # Identify and switch to the selected user by their email.
            selected_user_id = next((user['id'] for user in config_data['phase-users'] if user['email'] == email_selected), None)

            if selected_user_id:
                config_data['default-user'] = selected_user_id
                save_config(config_data)
                print(f"Switched to user: {selected}")
                break
            else:
                print("User switch failed.")
                break
    except KeyboardInterrupt:
        sys.exit(0)
