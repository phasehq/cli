import sys
import re
import json
import csv
import yaml
from phase_cli.utils.phase_io import Phase
import xml.sax.saxutils as saxutils
from phase_cli.utils.secret_referencing import resolve_all_secrets
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn


def phase_secrets_env_export(env_name=None, phase_app=None, keys=None, tags=None, format='dotenv', path: str = '/'):
    """
    Exports secrets from the specified environment with support for multiple export formats. 
    This function fetches secrets from Phase, resolves any cross-environment or local secret references, and then outputs them in the chosen format.

    Supports several formats for exporting secrets:
    - dotenv (.env): Key-value pairs in a simple text format.
    - JSON: JavaScript Object Notation, useful for integration with various tools and languages.
    - CSV: Comma-Separated Values, a simple text format for tabular data.
    - YAML: Human-readable data serialization format, often used for configuration files.
    - XML: Extensible Markup Language, suitable for complex data structures.
    - TOML: Tom's Obvious, Minimal Language, a readable configuration file format.
    - HCL: HashiCorp Configuration Language, used in HashiCorp tools like Terraform.
    - INI: A simple format often used for configuration files.
    - Java Properties: Key-value pair format commonly used in Java applications.

    Args:
        env_name (str, optional): The name of the environment from which to fetch secrets. If None, 
                                  the default environment is used. Defaults to None.
        phase_app (str, optional): The name of the Phase application to use. If None, the default 
                                   application context is used. Defaults to None.
        keys (list[str], optional): A list of specific secret keys to fetch. If None, all secrets 
                                    in the environment are fetched. Defaults to None.
        tags (str, optional): Comma-separated list of tags to filter secrets. Only secrets containing 
                              these tags will be fetched. Defaults to None.
        format (str, optional): The format for exporting the secrets. Supported formats include 
                                'dotenv', 'json', 'csv', 'yaml', 'xml', 'toml', 'hcl', 'ini', 
                                and 'java_properties'. Defaults to 'dotenv'.

    Raises:
        ValueError: If any errors occur during the fetching of secrets or if the specified format 
                    is not supported.
    """

    # Initialize
    phase = Phase()
    # Create a console object for logging warnings and errors to stderr
    console = Console(stderr=True)

    try:
        # Progress bar setup
        with Progress(
            *Progress.get_default_columns(),
            TextColumn("[bold green]{task.description}", justify="right"),
            BarColumn(bar_width=None),
            console=console,
            transient=True,
        ) as progress:
            task1 = progress.add_task("[bold green]Fetching secrets...", total=None)

            # Fetch all secrets
            all_secrets = phase.get(env_name=env_name, app_name=phase_app, tag=tags, path=path)

            # Organize all secrets into a dictionary for easier lookup.
            secrets_dict = {}
            for secret in all_secrets:
                env_name = secret['environment']
                key = secret['key']
                if env_name not in secrets_dict:
                    secrets_dict[env_name] = {}
                secrets_dict[env_name][key] = secret['value']

            resolved_secrets = []

            for secret in all_secrets:
                try:
                    # Ensure we use the correct environment name for each secret
                    current_env_name = secret['environment']
                    current_application_name = secret['application']

                    # Attempt to resolve secret references in the value
                    resolved_value = resolve_all_secrets(value=secret["value"], all_secrets=all_secrets, phase=phase, current_application_name=current_application_name, current_env_name=current_env_name)
                    resolved_secrets.append({
                        **secret,
                        "value": resolved_value  # Replace original value with resolved value
                    })
                except ValueError as e:
                    # Print warning to stderr via the error_console
                    console.log(f"Warning: {e}")
            
            # Ensure the progress bar and messages don't get piped to a file
            environments = {secret['environment'] for secret in all_secrets}
            environment_message = ', '.join(environments)
            secret_count = len(all_secrets)
            
            progress.update(task1, completed=100)  # Adjust completion as needed
            
            # Export success message
            console.log(f" 🥡 Exported [bold magenta]{secret_count}[/] secrets from the [bold green]{environment_message}[/] environment.\n")

            # Create a dictionary with keys and resolved values
            all_secrets_dict = {secret["key"]: secret["value"] for secret in resolved_secrets}

            # Filter secrets if specific keys are requested
            if keys:
                filtered_secrets_dict = {key: all_secrets_dict[key] for key in keys if key in all_secrets_dict}
            else:
                filtered_secrets_dict = all_secrets_dict

        if format == 'json':
            export_json(filtered_secrets_dict)
        elif format == 'csv':
            export_csv(filtered_secrets_dict)
        elif format == 'yaml':
            export_yaml(filtered_secrets_dict)
        elif format == 'xml':
            export_xml(filtered_secrets_dict)
        elif format == 'toml':
            export_toml(filtered_secrets_dict)
        elif format == 'hcl':
            export_hcl(filtered_secrets_dict)
        elif format == 'ini':
            export_ini(filtered_secrets_dict)
        elif format == 'java_properties':
            export_java_properties(filtered_secrets_dict)
        else:
            export_dotenv(filtered_secrets_dict)

    except ValueError as e:
        console.log(f"Error: {e}")


def export_json(secrets_dict):
    """Export secrets as JSON."""
    print(json.dumps(secrets_dict, indent=4))


def export_csv(secrets_dict):
    """Export secrets as CSV."""
    writer = csv.writer(sys.stdout)
    writer.writerow(['Key', 'Value'])
    for key, value in secrets_dict.items():
        writer.writerow([key, value])


def export_yaml(secrets_dict):
    """Export secrets as YAML."""
    print(yaml.dump(secrets_dict))


def export_toml(secrets_dict):
    """Export secrets as TOML."""
    for key, value in secrets_dict.items():
        print(f'{key} = "{value}"')


def export_xml(secrets_dict):
    """Export secrets as XML."""
    xml_output = '<Secrets>\n'
    for key, value in secrets_dict.items():
        escaped_value = saxutils.escape(value)
        xml_output += f'  <secret name="{key}">{escaped_value}</secret>\n' # Handle escaping
    xml_output += '</Secrets>'
    print(xml_output)


def export_dotenv(secrets_dict):
    """Export secrets in dotenv format."""
    for key, value in secrets_dict.items():
        print(f'{key}="{value}"')


def export_hcl(secrets_dict):
    """Export secrets as HCL."""
    for key, value in secrets_dict.items():
        escaped_value = value.replace('"', '\\"')  # Escape double quotes
        print(f'variable "{key}" {{')
        print(f'  default = "{escaped_value}"')
        print('}\n')


def export_ini(secrets_dict):
    """Export secrets as INI."""
    print("[DEFAULT]")  # Add a default section header
    for key, value in secrets_dict.items():
        escaped_value = value.replace('%', '%%')  # Escape percent signs
        print(f'{key} = {escaped_value}')


def export_java_properties(secrets_dict):
    """Export secrets as Java properties file."""
    for key, value in secrets_dict.items():
        print(f'{key}={value}')
