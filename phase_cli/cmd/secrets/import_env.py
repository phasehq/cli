import sys
from phase_cli.utils.phase_io import Phase
from phase_cli.utils.misc import get_default_user_id, sanitize_value
from rich.console import Console

def phase_secrets_env_import(env_file, env_name=None, phase_app=None, path: str = '/'):
    """
    Imports existing environment variables and secrets from a user's .env file.

    Args:
        env_file (str): Path to the .env file.
        env_name (str, optional): The name of the environment to which secrets should be saved. Defaults to None.
        phase_app (str, optional): The name of the Phase application. Defaults to None.

    Raises:
        FileNotFoundError: If the provided .env file is not found.
    """
    # Initialize the Phase class
    phase = Phase()
    console = Console()
    
    # Parse the .env file
    secrets = []
    try:
        with open(env_file) as f:
            for line in f:
                # Ignore lines that start with a '#' or don't contain an '='
                line = line.strip()
                if line.startswith('#') or '=' not in line:
                    continue
                key, _, value = line.partition('=')
                secrets.append((key.strip().upper(), sanitize_value(value.strip())))
    
    except FileNotFoundError:
        print(f"Error: The file {env_file} was not found.")
        sys.exit(1)
    
    try:
        # Encrypt and send secrets to the backend using the `create` method
        response = phase.create(key_value_pairs=secrets, env_name=env_name, app_name=phase_app, path=path)
        
        # Check the response status code
        if response.status_code == 200:
            print(f"Successfully imported and encrypted {len(secrets)} secrets.")
            if env_name == None:
                print("To view them please run: phase secrets list")
            else:
                print(f"To view them please run: phase secrets list --env {env_name}")
        else:
            # Print an error message if the response status code indicates an error
            print(f"Error: Failed to import secrets. HTTP Status Code: {response.status_code}")

    except ValueError as e:
        console.log(f"Error: {e}")
