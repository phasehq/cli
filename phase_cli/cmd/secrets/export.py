import sys
import re
import json
import csv
import yaml
from phase_cli.utils.phase_io import Phase
import xml.sax.saxutils as saxutils
from phase_cli.utils.const import cross_env_pattern, local_ref_pattern
from rich.console import Console

console = Console()

def phase_secrets_env_export(env_name=None, phase_app=None, keys=None, tags=None, format='dotenv'):
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

    try:
        # Fetch all secrets
        all_secrets = phase.get(env_name=env_name, app_name=phase_app, tag=tags)
        all_secrets_dict = {secret["key"]: secret["value"] for secret in all_secrets}

        # Resolve references
        resolved_secrets = resolve_references(all_secrets_dict, phase, env_name, phase_app)

        # Filter secrets if specific keys are requested
        secrets_dict = {key: resolved_secrets[key] for key in (keys or resolved_secrets)}

        # Export based on selected format
        if format == 'json':
            export_json(secrets_dict)
        elif format == 'csv':
            export_csv(secrets_dict)
        elif format == 'yaml':
            export_yaml(secrets_dict)
        elif format == 'xml':
            export_xml(secrets_dict)
        elif format == 'toml':
            export_toml(secrets_dict)
        elif format == 'hcl':
            export_hcl(secrets_dict)
        elif format == 'ini':
            export_ini(secrets_dict)
        elif format == 'java_properties':
            export_java_properties(secrets_dict)
        else:
            export_dotenv(secrets_dict)

    except ValueError as e:
        console.log(f"Error: {e}")

def resolve_references(secrets_dict, phase, env_name, phase_app):
    """
    Resolve references in secret values.
    """
    for key, value in secrets_dict.items():
        # Track found references to avoid duplicate warnings
        found_references = set()

        # Resolve cross-environment references
        cross_env_matches = re.findall(cross_env_pattern, value)
        for ref_env, ref_key in cross_env_matches:
            full_ref = f"{ref_env}.{ref_key}"
            found_references.add(full_ref)

            try:
                ref_secrets = phase.get(env_name=ref_env, keys=[ref_key], app_name=phase_app)
                if ref_secrets:
                    ref_secret = ref_secrets[0]
                    value = value.replace(f"${{{full_ref}}}", ref_secret['value'])
                else:
                    print(f"# Warning: Secret '{ref_key}' not found in environment '{ref_env}' for key '{key}'.")
            except ValueError as e:
                print(f"# Error: Issue with fetching secret '{ref_key}' from environment '{ref_env}' for key '{key}'. {e}")

        # Resolve local references
        local_ref_matches = re.findall(local_ref_pattern, value)
        for ref_key in local_ref_matches:
            if ref_key not in found_references:
                if ref_key in secrets_dict:
                    ref_value = secrets_dict[ref_key]
                    value = value.replace(f"${{{ref_key}}}", ref_value)
                else:
                    print(f"# Warning: Local reference '{ref_key}' not found for key '{key}'.")

        secrets_dict[key] = value

    return secrets_dict


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
