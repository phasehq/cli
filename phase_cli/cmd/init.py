import os
import sys
import json
import questionary
from phase_cli.utils.phase_io import Phase
from phase_cli.utils.const import PHASE_ENV_CONFIG

# Initializes a .phase.json in the root of the dir of where the command is run
def phase_init():
    """
    Initializes the Phase application by linking the user's project to a Phase app.
    """
    # Initialize the Phase class
    phase = Phase()

    try:
        data = phase.init()

        # Create dropdown choices including app name and UUID in brackets
        app_choices = [f"{app['name']} ({app['id']})" for app in data['apps']]
        app_choices.append('Exit')

        selected_app = questionary.select("Select an App:", choices=app_choices).ask()

        # Handle cases where the user cancels the selection or no valid selection is made
        if selected_app is None or selected_app == 'Exit':
           # print("Operation cancelled by user.")
            sys.exit(0)

        # Extract selected app's name and UUID from the selection
        app_id = selected_app.split(" (")[1].rstrip(")")
        selected_app_name = selected_app.split(" (")[0]

        selected_app_details = next(app for app in data['apps'] if app['id'] == app_id)
        
        # Find the 'Development' environment
        dev_env = next((env for env in selected_app_details['environment_keys']
                        if env['environment']['name'] == 'Development'), None)
        
        if not dev_env:
            raise ValueError("No 'Development' environment found.")

        # Save the selected app's details to .phase.json
        phase_env = {
            "version": "1",
            "phaseApp": selected_app_name,
            "appId": selected_app_details['id'],
            "defaultEnv": dev_env['environment']['name'],
        }

        # Create .phase.json
        with open(PHASE_ENV_CONFIG, 'w') as f:
            json.dump(phase_env, f, indent=2)
        os.chmod(PHASE_ENV_CONFIG, 0o600)

        print("✅ Initialization completed successfully.")

    except KeyboardInterrupt:
        # Handle the Ctrl+C event quietly
        sys.exit(0)
    except Exception as e:
        # Handle other exceptions if needed
        print(e)
        sys.exit(1)

