import os
import json
import webbrowser
from phase_cli.utils.misc import get_default_user_host, get_default_user_org, open_browser
from phase_cli.utils.const import PHASE_SECRETS_DIR

def phase_open_console():
    """Opens the Phase console in a web browser based on the default organization, application ID, and possibly the environment ID."""
    try:
        url_base = get_default_user_host()
        config_file_path = os.path.join(PHASE_SECRETS_DIR, 'config.json')
        org_name = get_default_user_org(config_file_path)
        
        phase_env_config_path = os.path.join(os.getcwd(), ".phase.json")
        if os.path.exists(phase_env_config_path):
            with open(phase_env_config_path, 'r') as file:
                config = json.load(file)
                app_id = config.get("appId")
                version = int(config.get("version", "1"))  # Default to version 1 if not specified
                
                if version >= 2 and "envId" in config:
                    env_id = config.get("envId")
                    url = f"{url_base}/{org_name}/apps/{app_id}/environments/{env_id}"
                else:
                    url = f"{url_base}/{org_name}/apps/{app_id}"
        else:
            url = url_base
        
        open_browser(url)
    except Exception as e:
        print(f"Error opening Phase console: {e}")
