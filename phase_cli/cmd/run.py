import sys
import os
import re
import subprocess
from phase_cli.utils.phase_io import Phase
from phase_cli.utils.const import cross_env_pattern, local_ref_pattern
from rich.console import Console
from rich.spinner import Spinner

def phase_run_inject(command, env_name=None, phase_app=None, tags=None):
    """
    Executes a shell command with environment variables set to the secrets 
    fetched from Phase for the specified environment.

    Args:
        command (str): The shell command to be executed.
        env_name (str, optional): The environment name from which secrets are fetched. Defaults to None.
        phase_app (str, optional): The name of the Phase application. Defaults to None.
    """
    phase = Phase()
    console = Console()
    status = console.status(Spinner("dots", text="Fetching secrets..."), spinner="dots")

    try:
        # Start the spinner
        status.start()

        # Fetch secrets from Phase
        secrets = phase.get(env_name=env_name, app_name=phase_app, tag=tags)
        new_env = os.environ.copy()

        # Create a dictionary from the fetched secrets for easy look-up
        secrets_dict = {secret["key"]: secret["value"] for secret in secrets}
        
        # Iterate through the secrets and resolve references
        for key, value in secrets_dict.items():
            
            # Resolve cross environment references
            cross_env_matches = re.findall(cross_env_pattern, value)
            for ref_env, ref_key in cross_env_matches:
                try:
                    ref_secret = phase.get(env_name=ref_env, keys=[ref_key], app_name=phase_app)[0]
                    value = value.replace(f"${{{ref_env}.{ref_key}}}", ref_secret['value'])
                except ValueError as e:
                    print(f"⚠️  Warning: The environment '{ref_env}' for key '{key}' either does not exist or you do not have access to it. Reference {ref_key} not found. Ignoring...")
                    value = value.replace(f"${{{ref_env}.{ref_key}}}", "")
            
            # Resolve local references
            local_ref_matches = re.findall(local_ref_pattern, value)
            for ref_key in local_ref_matches:
                value = value.replace(f"${{{ref_key}}}", secrets_dict.get(ref_key, f"⚠️  Warning: Local reference {ref_key} not found for key {key}. Ignoring..."))
            
            new_env[key] = value

        # Stop the spinner before running the command
        status.stop()

        # Run the command with the updated environment
        subprocess.run(command, shell=True, env=new_env)

    except ValueError as e:
        console.log(f"Error: {e}")
        sys.exit(1)
    finally:
        status.stop()