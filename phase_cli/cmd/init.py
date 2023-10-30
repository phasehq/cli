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
    except ValueError as err:
        print(err)
        return

    try:
        # Present a list of apps to the user and let them choose one
        app_choices = [app['name'] for app in data['apps']]
        app_choices.append('Exit')  # Add Exit option at the end

        selected_app_name = questionary.select(
            'Select an App:',
            choices=app_choices
        ).ask()

        # Check if the user selected the "Exit" option
        if selected_app_name == 'Exit':
            sys.exit(0)

        # Find the selected app's details
        selected_app_details = next(
            (app for app in data['apps'] if app['name'] == selected_app_name),
            None
        )

        # Check if selected_app_details is None (no matching app found)
        if selected_app_details is None:
            sys.exit(1)

        # Extract the default environment ID for the environment named "Development"
        default_env = next(
            (env_key for env_key in selected_app_details['environment_keys'] if env_key['environment']['name'] == 'Development'),
            None
        )

        if not default_env:
            raise ValueError("No 'Development' environment found.")

        # Save the selected app’s environment details to the .phase.json file
        phase_env = {
            "version": "1",
            "phaseApp": selected_app_name,
            "appId": selected_app_details['id'],  # Save the app id
            "defaultEnv": default_env['environment']['name'],
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

