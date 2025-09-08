#!/bin/python
import os
import sys
import traceback
import argparse
from argparse import RawTextHelpFormatter
from phase_cli.cmd.open_console import phase_open_console
from phase_cli.cmd.open_docs import phase_open_docs
from phase_cli.cmd.update import phase_cli_update
from phase_cli.cmd.users.whoami import phase_users_whoami
from phase_cli.cmd.users.switch import switch_user
from phase_cli.cmd.users.keyring import show_keyring_info
from phase_cli.cmd.users.logout import phase_cli_logout
from phase_cli.cmd.run import phase_run_inject
from phase_cli.cmd.shell import phase_shell
from phase_cli.cmd.init import phase_init
from phase_cli.cmd.auth.auth import phase_auth
from phase_cli.cmd.secrets.list import phase_list_secrets
from phase_cli.cmd.secrets.get import phase_secrets_get
from phase_cli.cmd.secrets.export import phase_secrets_env_export
from phase_cli.cmd.secrets.import_env import phase_secrets_env_import
from phase_cli.cmd.secrets.delete import phase_secrets_delete
from phase_cli.cmd.secrets.create import phase_secrets_create
from phase_cli.cmd.secrets.update import phase_secrets_update
from phase_cli.utils.const import __version__
from phase_cli.utils.const import phaseASCii, description
from rich.console import Console

def print_phase_cli_version():
    print(f"Version: {__version__}")

def print_phase_cli_version_only():
    print(f"{__version__}")

PHASE_DEBUG = os.environ.get('PHASE_DEBUG', 'False').lower() == 'true'

class CustomHelpFormatter(argparse.HelpFormatter):
    def __init__(self, prog):
        super().__init__(prog, max_help_position=15, width=sys.maxsize) # set the alignment and wrapping width

    def add_usage(self, usage, actions, groups, prefix=None):
        # Override to prevent the default behavior
        return 

    def _format_action(self, action):
        # If the action type is subparsers, skip its formatting
        if isinstance(action, argparse._SubParsersAction):
            # Filter out the metavar option
            action.metavar = None
        parts = super(CustomHelpFormatter, self)._format_action(action)
        # remove the unnecessary line
        if "{auth,init,run,shell,secrets,users,docs,console,update}" in parts:
            parts = parts.replace("{auth,init,run,shell,secrets,users,docs,console,update}", "")
        return parts

class HelpfulParser(argparse.ArgumentParser):
    def __init__(self, *args, **kwargs):
        kwargs['formatter_class'] = CustomHelpFormatter
        super().__init__(*args, **kwargs)
        
    def error(self, message):
        print (description)
        print(phaseASCii)
        self.print_help()
        sys.exit(0)

    def add_subparsers(self, **kwargs):
        kwargs['title'] = 'Commands'
        return super(HelpfulParser, self).add_subparsers(**kwargs)

def main ():
    env_help = "Environment name eg. dev, staging, production"
    tag_help = '🏷️: Comma-separated list of tags to filter the secrets. Tags are case-insensitive and support partial matching. For example, using --tags "prod,config" will include secrets tagged with "Production" or "ConfigData". Underscores in tags are treated as spaces, so "prod_data" matches "prod data".'
    app_help = 'The name of your Phase application. Optional: If you don\'t have a .phase.json file in your project directory or simply want to override it.'
    app_id_help = 'The ID of your Phase application. Takes precedence over --app if both are provided.'
    console = Console()

    try:
        parser = HelpfulParser(prog='phase-cli', formatter_class=RawTextHelpFormatter)
        parser.add_argument('--version', '-v', action='version', version=__version__)
        
        # Create subparsers with title 'Available Commands:'
        subparsers = parser.add_subparsers(dest='command', required=True)

        # Auth command
        auth_parser = subparsers.add_parser('auth', help='💻 Authenticate with Phase')
        auth_parser.add_argument('--mode', choices=['token', 'webauth', 'aws-iam'], default='webauth', help='Mode of authentication. Default: webauth')
        auth_parser.add_argument('--service-account-id', type=str, help='Service Account ID for when using external identities for authentication.')
        auth_parser.add_argument('--ttl', type=int, help='Token TTL in seconds for tokens created using external identities.')
        auth_parser.add_argument('--no-login', action='store_true', help='For external identity modes (e.g., aws-iam): print authentication tokens response to stdout and without logging in.')

        # Init command
        init_parser = subparsers.add_parser('init', help='🔗 Link your project with your Phase app')

        # Run command
        run_parser = subparsers.add_parser('run', help='🚀 Run and inject secrets to your app')
        run_parser.add_argument('command_to_run', nargs=argparse.REMAINDER, help='Command to be run. Ex. phase run yarn dev')
        run_parser.add_argument('--env', type=str, help=env_help)
        run_parser.add_argument('--app', type=str, help=app_help)
        run_parser.add_argument('--app-id', type=str, help=app_id_help)
        run_parser.add_argument('--path', type=str, default='/', help="Specific path under which to fetch secrets from and inject into your application. Default is '/'. Pass an empty string "" to fetch secrets from all paths.")
        run_parser.add_argument('--tags', type=str, help=tag_help)

        # Shell command
        shell_parser = subparsers.add_parser('shell', help='🐚 Launch a sub-shell with secrets as environment variables (BETA)')
        shell_parser.add_argument('--env', type=str, help=env_help)
        shell_parser.add_argument('--app', type=str, help=app_help)
        shell_parser.add_argument('--app-id', type=str, help=app_id_help)
        shell_parser.add_argument('--path', type=str, default='/', help="Specific path under which to fetch secrets from and inject into your shell. Default is '/'. Pass an empty string \"\" to fetch secrets from all paths.")
        shell_parser.add_argument('--tags', type=str, help=tag_help)
        shell_parser.add_argument('--shell', type=str, help="Specify which shell to use (bash, zsh, sh, fish, powershell, etc). If not specified, will use the current shell or system default.")

        # Secrets command
        secrets_parser = subparsers.add_parser('secrets', help='🗝️\u200A Manage your secrets')
        secrets_subparsers = secrets_parser.add_subparsers(dest='secrets_command', required=True)

        # Secrets list command
        secrets_list_parser = secrets_subparsers.add_parser('list', help='📇 List all the secrets')
        secrets_list_parser.add_argument('--show', action='store_true', help='Return secrets uncensored')
        secrets_list_parser.add_argument('--env', type=str, help=env_help)
        secrets_list_parser.add_argument('--app', type=str, help=app_help)
        secrets_list_parser.add_argument('--app-id', type=str, help=app_id_help)
        secrets_list_parser.add_argument('--path', type=str, help="The path in which you want to list secrets.")
        secrets_list_parser.add_argument('--tags', type=str, help=tag_help)
        secrets_list_parser.epilog = (
            "🔗 : Indicates that the secret value references another secret within the same environment.\n"
            "⛓️ : Indicates a cross-environment reference, where a secret in the current environment references a secret from another environment.\n"
            "🏷️ : Indicates a tag is associated with a secret.\n"
            "💬 : Indicates a comment is associated with a given secret.\n" 
            "🔏 : Indicates a personal secret, visible only to the user who set it."

        )

        # Secrets get command
        secrets_get_parser = secrets_subparsers.add_parser('get', help='🔍 Fetch details about a secret in JSON')
        secrets_get_parser.add_argument('key', type=str, help='The key associated with the secret to fetch')
        secrets_get_parser.add_argument('--env', type=str, help=env_help)
        secrets_get_parser.add_argument('--app', type=str, help=app_help)
        secrets_get_parser.add_argument('--app-id', type=str, help=app_id_help)
        secrets_get_parser.add_argument('--tags', type=str, help=tag_help)
        secrets_get_parser.add_argument('--path', type=str, default='/', required=False, help="The path from which to fetch the secret from. Default is '/'. Pass an empty string \"\" to fetch secrets from all paths.")

        # Secrets create command
        secrets_create_parser = secrets_subparsers.add_parser(
            'create', 
            description='💳 Create a new secret. Optionally, you can provide the secret value via stdin, or generate a random value of a specified type and length.\n\nExamples:\n  cat ~/.ssh/id_rsa | phase secrets create SSH_PRIVATE_KEY\n  phase secrets create RAND --random hex --length 32',
            help='💳 Create a new secret'
        )
        secrets_create_parser.add_argument(
            'key', 
            type=str, 
            nargs='?', 
            help='The key for the secret to be created. (Will be converted to uppercase.) If the value is not provided as an argument, it will be read from stdin.'
        )
        secrets_create_parser.add_argument('--env', type=str, help=env_help)
        secrets_create_parser.add_argument('--app', type=str, help=app_help)
        secrets_create_parser.add_argument('--app-id', type=str, help=app_id_help)
        secrets_create_parser.add_argument('--path', type=str, default='/', help="The path in which you want to create a secret. You can create a directory by simply specifying a path like so: --path /folder/SECRET. Default is '/'")
        
        # Handle the --random argument
        random_types = ['hex', 'alphanumeric', 'base64', 'base64url', 'key128', 'key256']
        secrets_create_parser.add_argument('--random', 
                                        type=str, 
                                        choices=random_types, 
                                        help='🎲 Specify the type of random value to generate. Available types: ' + ', '.join(random_types) + '. Example usage: --random hex')

        # Handle the --length argument
        secrets_create_parser.add_argument('--length', 
                                        type=int, 
                                        default=32, 
                                        help='🔢 Specify the length of the random value. Applicable for types other than key128 and key256. Default is 32. Example usage: --length 16')

        # Handle the --override argument
        secrets_create_parser.add_argument('--override', 
                                        action='store_true', 
                                        help='🔏 Specify if the secret is a personal override. Default is False.')

        # Secrets update command
        secrets_update_parser = secrets_subparsers.add_parser(
            'update', 
            description='📝 Update an existing secret. Optionally, you can provide the new secret value via stdin or generate a random value of a specified type and length.\n\nExample:\n  cat ~/.ssh/id_ed25519 | phase secrets update SSH_PRIVATE_KEY\n  phase secrets update MY_SECRET_KEY --random hex --length 32',
            help='📝 Update an existing secret'
        )
        secrets_update_parser.add_argument(
            'key', 
            type=str,
            nargs='?',
            help='The key associated with the secret to update. If the new value is not provided as an argument, it will be read from stdin.'
        )
        secrets_update_parser.add_argument('--env', type=str, help=env_help)
        secrets_update_parser.add_argument('--app', type=str, help=app_help)
        secrets_update_parser.add_argument('--app-id', type=str, help=app_id_help)

        # Handle the --random argument
        random_types = ['hex', 'alphanumeric', 'base64', 'base64url', 'key128', 'key256']
        secrets_update_parser.add_argument('--random', 
                                            type=str, 
                                            choices=random_types, 
                                            help='🎲 Specify the type of random value to generate. Available types: ' + ', '.join(random_types) + '. Example usage: --random hex')

        # Handle the --length argument
        secrets_update_parser.add_argument('--length', 
                                            type=int, 
                                            default=32, 
                                            help='🔢 Specify the length of the random value. Applicable for types other than key128 and key256. Default is 32. Example usage: --length 16')

        # Handle the --path and --updated-path arguments for path management
        secrets_update_parser.add_argument('--path', 
                                            type=str, 
                                            default='/', 
                                            help='The current path of the secret to update. Defaults to the root path \'/\'. Example usage: --path "/folder/subfolder"')
        secrets_update_parser.add_argument('--updated-path', 
                                            type=str, 
                                            help='The new path for the secret, if changing its location. If not provided, the secret\'s path is not updated. Example usage: --updated-path "/folder/subfolder"')

        # Handle the --override argument for personal secret override
        secrets_update_parser.add_argument('--override', 
                                            action='store_true', 
                                            help='🔏 Update the personal override value.')

        # Handle the --toggle-override argument to toggle the override state
        secrets_update_parser.add_argument('--toggle-override', 
                                            action='store_true', 
                                            help='🔄 Toggle the override state between active and inactive.')

        # Secrets delete command
        secrets_delete_parser = secrets_subparsers.add_parser('delete', help='🗑️\u200A Delete a secret')
        secrets_delete_parser.add_argument('keys', nargs='*', help='Keys to be deleted')
        secrets_delete_parser.add_argument('--env', type=str, help=env_help)
        secrets_delete_parser.add_argument('--app', type=str, help=app_help)
        secrets_delete_parser.add_argument('--app-id', type=str, help=app_id_help)

        # Handle the --path argument
        secrets_delete_parser.add_argument('--path', 
                                        type=str, 
                                        default='/', 
                                        help='The path within which to delete the secrets. If specified, only deletes secrets within this path. Defaults to the root path \'/\'. Example usage: --path "/myfolder/subfolder"')

        # Secrets import command
        secrets_import_parser = secrets_subparsers.add_parser('import', help='📩 Import secrets from a .env file')
        secrets_import_parser.add_argument('env_file', type=str, help='The .env file to import')
        secrets_import_parser.add_argument('--env', type=str, help=env_help)
        secrets_import_parser.add_argument('--app', type=str, help=app_help)
        secrets_import_parser.add_argument('--app-id', type=str, help=app_id_help)
        secrets_import_parser.add_argument('--path', type=str, default='/', help="The path to which you want to import secret(s). Default is '/'")

        # Secrets export command
        secrets_export_parser = secrets_subparsers.add_parser('export', help='🥡 Export secrets in a specific format')
        secrets_export_parser.add_argument('keys', nargs='*', help='List of keys separated by space', default=None)
        secrets_export_parser.add_argument('--env', type=str, help=env_help)
        secrets_export_parser.add_argument('--app', type=str, help=app_help)
        secrets_export_parser.add_argument('--app-id', type=str, help=app_id_help)
        secrets_export_parser.add_argument('--path', type=str, default='/', help="The path from which you want to export secret(s). Default is '/'. Pass an empty string \"\" to export secrets from all paths.")
        secrets_export_parser.add_argument('--format', type=str, default='dotenv', 
            choices=['dotenv', 'json', 'csv', 'yaml', 'xml', 'toml', 'hcl', 'ini', 'java_properties', 'kv'], 
            help='Specifies the export format. Supported formats: dotenv (default), kv, json, csv, yaml, xml, toml, hcl, ini, java_properties.')
        secrets_export_parser.add_argument('--tags', type=str, help=tag_help)

        # Users command
        users_parser = subparsers.add_parser('users', help='👥 Manage users and accounts')
        users_subparsers = users_parser.add_subparsers(dest='users_command', required=True)

        # Users whoami command
        whoami_parser = users_subparsers.add_parser('whoami', help='🙋 See details of the current user')

        # Users switch command
        switch_parser = users_subparsers.add_parser('switch', help='🪄\u200A Switch between Phase users, orgs and hosts')

        # Users logout command
        logout_parser = users_subparsers.add_parser('logout', help='🏃 Logout from phase-cli')
        logout_parser.add_argument('--purge', action='store_true', help='Purge all local data')

        # Users keyring command
        keyring_parser = users_subparsers.add_parser('keyring', help='🔐 Display information about the Phase keyring')
        
        # Open the Phase Docs
        docs_parser = subparsers.add_parser('docs', help='📖 Open the Phase CLI Docs in your browser')

        # Open the Phase Console
        web_parser = subparsers.add_parser('console', help='🖥️\u200A Open the Phase Console in your browser')

        # Check if the operating system is Linux before adding the update command
        if sys.platform == "linux":
            update_parser = subparsers.add_parser('update', help='🆙 Update the Phase CLI to the latest version')

        args = parser.parse_args()

        if args.command == 'auth':
            phase_auth(args.mode, service_account_id=args.service_account_id, ttl=args.ttl, no_login=args.no_login)
            sys.exit(0)
        elif args.command == 'init':
            phase_init()
        elif args.command == 'run':
            command = ' '.join(args.command_to_run)
            phase_run_inject(command, env_name=args.env, phase_app=args.app, phase_app_id=args.app_id, path=args.path, tags=args.tags)
        elif args.command == 'shell':
            phase_shell(env_name=args.env, phase_app=args.app, phase_app_id=args.app_id, path=args.path, tags=args.tags, shell_type=args.shell)
        elif args.command == 'console':
            phase_open_console()
        elif args.command == 'docs':
            phase_open_docs()
        elif args.command == 'update':
            phase_cli_update()
            sys.exit(0)
        elif args.command == 'users':
            if args.users_command == 'whoami':
                phase_users_whoami()
            elif args.users_command == 'switch':
                switch_user()
            elif args.users_command == 'logout':
                phase_cli_logout(args.purge)
            elif args.users_command == 'keyring':
                show_keyring_info()
            else:
                print("Unknown users sub-command: " + args.users_command)
                parser.print_help()
                sys.exit(1)
        elif args.command == 'secrets':
            if args.secrets_command == 'list':
                phase_list_secrets(args.show, env_name=args.env, phase_app=args.app, phase_app_id=args.app_id, path=args.path, tags=args.tags)
            elif args.secrets_command == 'get':
                phase_secrets_get(args.key, env_name=args.env, phase_app=args.app, phase_app_id=args.app_id, path=args.path, tags=args.tags)  
            elif args.secrets_command == 'create':
                phase_secrets_create(args.key, env_name=args.env, phase_app=args.app, phase_app_id=args.app_id, path=args.path, random_type=args.random, random_length=args.length, override=args.override)
            elif args.secrets_command == 'delete':
                phase_secrets_delete(args.keys, env_name=args.env, path=args.path, phase_app=args.app, phase_app_id=args.app_id)  
            elif args.secrets_command == 'import':
                phase_secrets_env_import(args.env_file, env_name=args.env, path=args.path, phase_app=args.app, phase_app_id=args.app_id)
            elif args.secrets_command == 'export':
                phase_secrets_env_export(env_name=args.env, keys=args.keys, phase_app=args.app, phase_app_id=args.app_id, path=args.path, tags=args.tags, format=args.format)
            elif args.secrets_command == 'update':
                phase_secrets_update(args.key, env_name=args.env, phase_app=args.app, phase_app_id=args.app_id, source_path=args.path, destination_path=args.updated_path, random_type=args.random, random_length=args.length, override=args.override, toggle_override=args.toggle_override)
            else:
                print("Unknown secrets sub-command: " + args.secrets_command)
                parser.print_help()
                sys.exit(1)
    except KeyboardInterrupt:
        print("\nStopping Phase.")
        sys.exit(0)
        
    except Exception as e:
        if os.getenv("PHASE_DEBUG") == "True":
            # When PHASE_DEBUG is set to True, print the full traceback
            traceback.print_exc()
        else:
            # When PHASE_DEBUG is set to False, print only the error message
            console.log(f"Error: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
