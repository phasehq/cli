import sys
import os
import subprocess
from phase_cli.utils.phase_io import Phase
from phase_cli.utils.misc import tag_matches, normalize_tag
from phase_cli.utils.secret_referencing import resolve_all_secrets
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TimeElapsedColumn

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
    console = Console()

    try:
        with Progress(
                SpinnerColumn(),
                *Progress.get_default_columns(),
                console=console,
                transient=True,
            ) as progress:
                task1 = progress.add_task("[bold green]Fetching secrets...", total=None)        

                # Fetch all secrets
                all_secrets = phase.get(env_name=env_name, app_name=phase_app, tag=tags, path=path)
                
                # Organize all secrets into a dictionary for easier lookup
                secrets_dict = {}
                for secret in all_secrets:
                    env_name = secret['environment']
                    secret_path = secret['path']
                    key = secret['key']
                    if env_name not in secrets_dict:
                        secrets_dict[env_name] = {}
                    if secret_path not in secrets_dict[env_name]:
                        secrets_dict[env_name][secret_path] = {}
                    secrets_dict[env_name][secret_path][key] = secret['value']

                # Resolve all secret references
                resolved_secrets_dict = {}
                for secret in all_secrets:
                    # Attempt to resolve secret references in the value
                    resolved_value = resolve_all_secrets(secret["value"], all_secrets, phase, secret.get('application'), secret.get('environment'))
                    resolved_secrets_dict[secret["key"]] = resolved_value

                # Count and get environment from the secrets for the message
                secret_count = len(resolved_secrets_dict)
                environments = set(secret.get('environment') for secret in all_secrets if secret['key'] in resolved_secrets_dict)
                environment_message = ', '.join(environments)

                new_env = os.environ.copy()
                new_env.update(resolved_secrets_dict)

                # Stop the fetching secrets spinner
                progress.stop()

                # Print the message with the number of secrets injected
                console.log(f"🚀 Injected [bold magenta]{secret_count}[/] secrets from the [bold green]{environment_message}[/] environment.\n")
                subprocess.run(command, shell=True, env=new_env)

    except ValueError as e:
        console.log(f"Error: {e}")
        sys.exit(1)
