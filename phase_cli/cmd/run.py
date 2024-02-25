import sys
import os
import subprocess
from phase_cli.utils.phase_io import Phase
from phase_cli.utils.misc import tag_matches, normalize_tag
from phase_cli.utils.secret_referencing import resolve_all_secrets
from rich.console import Console
from rich.spinner import Spinner

console = Console()

def phase_run_inject(command, env_name=None, phase_app=None, tags=None, path: str = '/'):
    """
    Executes a shell command with environment variables set to the secrets 
    fetched from Phase for the specified environment, resolving references as needed.

    Args:
        command (str): The shell command to be executed.
        env_name (str, optional): The environment name from which secrets are fetched. Defaults to None.
        phase_app (str, optional): The name of the Phase application. Defaults to None.
        tags (str, optional): Comma-separated list of tags to filter secrets. Defaults to None.
    """
    phase = Phase()
    status = console.status(Spinner("dots", text="Fetching secrets..."), spinner="dots")

    try:
        status.start()

        # Fetch all secrets without filtering by tags
        all_secrets = phase.get(env_name=env_name, app_name=phase_app, path=path)
        
        # Initialize an empty dictionary for the resolved secrets
        secrets_dict = {}

        # Attempt to resolve references in all secrets, logging warnings for any errors
        for secret in all_secrets:
            try:
                current_env_name = secret.get('environment', env_name)
                resolved_value = resolve_all_secrets(value=secret["value"], current_env_name=current_env_name, phase=phase)
                secrets_dict[secret["key"]] = resolved_value
            except ValueError as e:
                console.log(f"Warning: {e}")

        # Normalize and filter secrets by tags if tags are provided
        if tags:
            user_tags = [normalize_tag(tag) for tag in tags.split(',')]
            tagged_secrets = [secret for secret in all_secrets if any(tag_matches(secret.get("tags", []), user_tag) for user_tag in user_tags)]
            secrets_dict = {secret["key"]: secrets_dict.get(secret["key"], "") for secret in tagged_secrets}

        new_env = os.environ.copy()
        new_env.update(secrets_dict)

        status.stop()

        subprocess.run(command, shell=True, env=new_env)

    except ValueError as e:
        console.log(f"Error: {e}")
        sys.exit(1)
    finally:
        status.stop()
