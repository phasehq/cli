from phase_cli.utils.phase_io import Phase
from rich.console import Console
import json

def phase_secrets_get(key, env_name=None, phase_app=None, tags=None, path='/'):
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
        
        secrets_data = phase.get(env_name=env_name, keys=[key], app_name=phase_app, tag=tags, path=path)
        
        # Find the specific secret for the given key within the provided path
        secret_data = next((secret for secret in secrets_data if secret["key"] == key), None)
        
        # Check that secret_data was found and is a dictionary
        if not secret_data:
            console.log("🔍 Secret not found...")
            return
        if not isinstance(secret_data, dict):
            raise ValueError("Unexpected format: secret data is not a dictionary")
        
        # Convert secret data to JSON and print with syntax highlighting
        json_data = json.dumps(secret_data, indent=4)
        print(json_data)

    except ValueError as e:
        console.log(f"Error: {e}")
