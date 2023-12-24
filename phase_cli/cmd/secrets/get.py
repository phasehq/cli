from phase_cli.utils.phase_io import Phase
from rich import print as rich_print
from rich.json import JSON
from rich.console import Console
import json

def phase_secrets_get(key, env_name=None, phase_app=None, tags=None):
    """
    Fetch and print a single secret based on a given key as beautified JSON with syntax highlighting.
    
    :param key: The key associated with the secret to fetch.
    :param env_name: The name of the environment, if any. Defaults to None.
    """

    phase = Phase()
    console = Console()
    
    try:
        key = key.upper()
        secrets_data = phase.get(env_name=env_name, keys=[key], app_name=phase_app, tag=tags)
        
        # Find the specific secret for the given key
        secret_data = next((secret for secret in secrets_data if secret["key"] == key), None)
        
        # Check that secret_data was found and is a dictionary
        if not secret_data:
            print("🔍 Secret not found...")
            return
        if not isinstance(secret_data, dict):
            raise ValueError("Unexpected format: secret data is not a dictionary")
        
        # Convert secret data to JSON and print with syntax highlighting
        json_data = json.dumps(secret_data, indent=4)
        rich_print(JSON(json_data))

    except ValueError as e:
        console.log(f"Error: {e}")
