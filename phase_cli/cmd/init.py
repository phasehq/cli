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
            sys.exit(0)

        app_id = selected_app.split(" (")[1].rstrip(")")
        selected_app_name = selected_app.split(" (")[0]
        selected_app_details = next(app for app in data['apps'] if app['id'] == app_id)

        # Environment list sort order
        env_sort_order = {"DEV": 1, "STAGING": 2, "PROD": 3}

        # Stage 2: Choose environment, sorted by predefined order
        env_choices = sorted(
            selected_app_details['environment_keys'],
            key=lambda env: env_sort_order.get(env['environment']['env_type'], 4)
        )

        # Map environment names to their IDs, but only showing names in the choices
        env_choice_map = {env['environment']['name']: env['environment']['id'] for env in env_choices}
        env_choices_display = list(env_choice_map.keys()) + ['Exit']

        selected_env = questionary.select("Choose a Default Environment:", choices=env_choices_display).ask()

        if selected_env is None or selected_env == 'Exit':
            sys.exit(0)

        env_id = env_choice_map[selected_env]
        selected_env_name = selected_env
        
        # Ask the user if they want this configuration to apply to subdirectories
        apply_to_subdirs = questionary.confirm("🍱 Monorepo support: Would you like this configuration to apply to subdirectories?", default=False).ask()

        # Save the selected app's and environment's details to .phase.json
        phase_env = {
            "version": "2",
            "phaseApp": selected_app_name,
            "appId": selected_app_details['id'],
            "defaultEnv": selected_env_name,
            "envId": env_id,
            "monorepoSupport": apply_to_subdirs
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
