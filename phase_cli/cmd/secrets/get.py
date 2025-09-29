import sys
from phase_cli.utils.phase_io import Phase
from rich.console import Console
import json

def phase_secrets_get(key, env_name=None, phase_app=None, phase_app_id=None, tags=None, path='/', generate_leases: str = 'true', lease_ttl: int = None):
    """
    Fetch and print a single secret based on a given key as beautified JSON with syntax highlighting.

    :param key: The key associated with the secret to fetch.
    :param env_name: The name of the environment, if any. Defaults to None.
    :param phase_app: The name of the application, if any. Defaults to None.
    :param tags: Tags to match for the secret, if any. Defaults to None.
    :param path: The path under which to fetch secrets. Defaults to root ('/').
    """

    phase = Phase()
    console = Console()
    
    try:
        key = key.upper()
        lease_flag = str(generate_leases).lower() not in ['false', '0', 'no']
        secrets_data = phase.get(env_name=env_name, keys=[key], app_name=phase_app, app_id=phase_app_id, tag=tags, path=path, dynamic=True, lease=lease_flag, lease_ttl=lease_ttl)
        
        # Find the specific secret for the given key within the provided path
        secret_data = next((secret for secret in secrets_data if secret["key"] == key), None)
        
        # Check that secret_data was found and is a dictionary
        if not secret_data:
            console.log("🔍 Secret not found...")
            sys.exit(1)
        if not isinstance(secret_data, dict):
            raise ValueError("Unexpected format: secret data is not a dictionary")
        
        # Convert secret data to JSON and print with syntax highlighting
        json_data = json.dumps(secret_data, indent=4)
        print(json_data)

    except ValueError as e:
        console.log(f"Error: {e}")
        sys.exit(1)
