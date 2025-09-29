import sys
import os
import subprocess
from rich.console import Console
from rich.progress import Progress, SpinnerColumn
from phase_cli.utils.phase_io import Phase
from phase_cli.utils.secret_referencing import resolve_all_secrets
from phase_cli.utils.misc import get_default_shell, get_shell_command, clean_subprocess_env, parse_bool_flag

def phase_shell(env_name=None, phase_app=None, phase_app_id=None, tags=None, path: str = '/', shell_type=None, generate_leases: str = 'true', lease_ttl: int = None):
    """
    Launches an interactive shell with environment variables set to the secrets 
    fetched from Phase for the specified environment, resolving references as needed.

    Args:
        env_name (str, optional): The environment name from which secrets are fetched. Defaults to None.
        phase_app (str, optional): The name of the Phase application. Defaults to None.
        phase_app_id (str, optional): The ID of the Phase application. Defaults to None.
        tags (str, optional): Comma-separated list of tags to filter secrets. Defaults to None.
        path (str, optional): Specific path under which to fetch secrets. Defaults to '/'.
        shell_type (str, optional): Type of shell to launch (bash, zsh, fish, powershell, etc.). Defaults to None.
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
                lease_flag = parse_bool_flag(generate_leases)
                all_secrets = phase.get(env_name=env_name, app_name=phase_app, app_id=phase_app_id, tag=tags, path=path, dynamic=True, lease=lease_flag, lease_ttl=lease_ttl)
                
                # Organize all secrets into a dictionary for easier lookup
                secrets_dict = {}
                for secret in all_secrets:
                    secret_env_name = secret['environment']
                    secret_path = secret['path']
                    key = secret['key']
                    if secret_env_name not in secrets_dict:
                        secrets_dict[secret_env_name] = {}
                    if secret_path not in secrets_dict[secret_env_name]:
                        secrets_dict[secret_env_name][secret_path] = {}
                    secrets_dict[secret_env_name][secret_path][key] = secret['value']

                # Resolve all secret references
                resolved_secrets_dict = {}
                for secret in all_secrets:
                    # Attempt to resolve secret references in the value
                    if secret["value"] is None:
                        continue
                    resolved_value = resolve_all_secrets(secret["value"], all_secrets, phase, secret.get('application'), secret.get('environment'))
                    resolved_secrets_dict[secret["key"]] = resolved_value

                # Count and get environment from the secrets for the message
                secret_count = len(resolved_secrets_dict)
                
                # Extract application and environment names
                applications = set(secret.get('application') for secret in all_secrets if secret['key'] in resolved_secrets_dict and secret.get('application'))
                environments = set(secret.get('environment') for secret in all_secrets if secret['key'] in resolved_secrets_dict)
                
                application_message = ', '.join(applications)
                environment_message = ', '.join(environments)

                secrets_env = clean_subprocess_env()

                # Overlay resolved secrets (cast to str and ignore Nones)
                for k, v in resolved_secrets_dict.items():
                    if v is None:
                        continue
                    secrets_env[str(k)] = str(v)

                # Set a PHASE_* environment variable for shell scripts to detect
                secrets_env['PHASE_SHELL'] = 'true'
                if environments:
                    secrets_env['PHASE_ENV'] = list(environments)[0]
                if applications:
                    secrets_env['PHASE_APP'] = list(applications)[0]

                # Ensure TERM is present for proper line-editing/rendering in shells like zsh
                if not secrets_env.get('TERM'):
                    secrets_env['TERM'] = 'xterm-256color'
                
                # Determine which shell to launch
                if shell_type:
                    shell_cmd = get_shell_command(shell_type)
                else:
                    shell_cmd = get_default_shell()

                if not shell_cmd:
                    console.log("[bold red]Error:[/] Unable to determine shell to launch. Please specify a shell using --shell.")
                    sys.exit(1)

                shell_name = os.path.basename(shell_cmd[0])

                # Stop the fetching secrets spinner
                progress.stop()

                # Print the message with the number of secrets injected
                if path and path != '/':
                    console.log(f"🐚 Initialized [bold green]{shell_name}[/] with [bold magenta]{secret_count}[/] secrets from Application: [bold cyan]{application_message}[/], Environment: [bold green]{environment_message}[/], Path: [bold yellow]{path}[/]")
                else:
                    console.log(f"🐚 Initialized [bold green]{shell_name}[/] with [bold magenta]{secret_count}[/] secrets from Application: [bold cyan]{application_message}[/], Environment: [bold green]{environment_message}[/]")
                
                console.log(f"[bold yellow]Remember:[/] Secrets are only available in this session. Type [bold]exit[/] or press [bold]Ctrl+D[/] to exit.\n")
                
                # Launch the interactive shell
                try:
                    subprocess.run(shell_cmd, env=secrets_env, shell=False)
                    console.log(f"\n[bold red]🐚 Shell session ended.[/] Phase secrets are no longer available.")
                except Exception as e:
                    console.log(f"[bold red]Error launching shell:[/] {e}")
                    sys.exit(1)

    except ValueError as e:
        console.log(f"Error: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        console.log("\n[bold yellow]Shell launch interrupted.[/]")
        sys.exit(0)
