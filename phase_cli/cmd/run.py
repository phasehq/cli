import sys
import os
import re
import subprocess
from phase_cli.utils.phase_io import Phase
from phase_cli.utils.misc import tag_matches, normalize_tag
from phase_cli.utils.const import cross_env_pattern, local_ref_pattern
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
        secrets_dict = {secret["key"]: secret["value"] for secret in all_secrets}

        # Resolve references in all secrets
        for key, value in secrets_dict.items():
            value = resolve_secret(value, secrets_dict, phase, env_name, phase_app)
            secrets_dict[key] = value

        # Normalize and filter secrets by tags if tags are provided
        if tags:
            user_tags = [normalize_tag(tag) for tag in tags.split(',')]
            tagged_secrets = [secret for secret in all_secrets if any(tag_matches(secret.get("tags", []), user_tag) for user_tag in user_tags)]
            secrets_dict = {secret["key"]: secrets_dict[secret["key"]] for secret in tagged_secrets}


        new_env = os.environ.copy()
        new_env.update(secrets_dict)

        status.stop()

        subprocess.run(command, shell=True, env=new_env)

    except ValueError as e:
        console.log(f"Error: {e}")
        sys.exit(1)
    finally:
        status.stop()

def resolve_secret(value, secrets_dict, phase, env_name, phase_app):
    """
    Resolve references in a secret value.

    Args:
        value (str): The secret value to resolve.
        secrets_dict (dict): Dictionary of already fetched secrets.
        phase (Phase): Phase instance.
        env_name (str): Environment name.
        phase_app (str): Phase application name.

    Returns:
        str: Resolved secret value.
    """
    cross_env_matches = re.findall(cross_env_pattern, value)
    checked_environments = {}  # To track checked environments

    for ref_env, ref_key in cross_env_matches:
        if ref_env in checked_environments:
            # Skip processing if we already know the environment doesn't exist
            continue

        try:
            ref_secret = phase.get(env_name=ref_env, keys=[ref_key], app_name=phase_app)
            if ref_secret:
                value = value.replace(f"${{{ref_env}.{ref_key}}}", ref_secret[0]['value'])
            else:
                # Log a warning only if the environment exists but the secret doesn't
                console.log(f"⚠️  Warning: Secret '{ref_key}' not found in environment '{ref_env}'. Ignoring...")
                value = value.replace(f"${{{ref_env}.{ref_key}}}", "")
        except Exception as e:
            if "environment does not exist" in str(e) or "do not have access" in str(e):
                # Log this warning only once per environment
                if ref_env not in checked_environments:
                    console.log(f"⚠️  Warning: Environment '{ref_env}' does not exist or is inaccessible.")
                    checked_environments[ref_env] = True
                value = value.replace(f"${{{ref_env}.{ref_key}}}", "")
            else:
                console.log(f"⚠️  Warning: Error accessing secret '{ref_key}' in environment '{ref_env}': {e}. Ignoring...")
                value = value.replace(f"${{{ref_env}.{ref_key}}}", "")

    local_ref_matches = re.findall(local_ref_pattern, value)
    for ref_key in local_ref_matches:
        if ref_key in secrets_dict:
            ref_value = secrets_dict[ref_key]
            value = value.replace(f"${{{ref_key}}}", ref_value)
        else:
            console.log(f"⚠️  Warning: Local reference '{ref_key}' not found. Ignoring...")

    return value