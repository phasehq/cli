import json
import os
from questionary import select, Separator
from phase_cli.utils.const import CONFIG_FILE

def load_config():
    if not os.path.exists(CONFIG_FILE):
        print("Configuration file does not exist.")
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

    # Prepend a 'title choice' with a Separator for visual effect.
    user_choices = [
        Separator("✉️\u200A Email - 🏢 Organization - 🌐 Host")
    ]
    
    user_choices += [
        f"{user['email']}, {user.get('organization_name', 'N/A')}, {user['host']}"
        for user in config_data['phase-users']
    ]

    while True:
        selected = select(
            "Choose a user to switch to:",
            choices=user_choices
        ).ask()

        # Re-show the selection prompt if the 'title choice' is selected.
        if selected.startswith("✉️ Email, 🏢 Org, 🌐 Host"):
            continue  # This effectively ignores the selection and prompts again.

        # Extract email from the selected choice as the unique identifier
        email_selected = selected.split(", ")[0].replace("✉️ ", "")

        # Find the ID of the selected user by email
        selected_user_id = None
        for user in config_data['phase-users']:
            if user['email'] == email_selected:
                selected_user_id = user['id']
                break

        if selected_user_id:
            config_data['default-user'] = selected_user_id
            save_config(config_data)
            print(f"Switched to user: {selected}")
            break  # Exit after successful switch
        else:
            print("User switch failed.")
            break  # Or consider retrying
