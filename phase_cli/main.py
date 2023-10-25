#!/bin/python
import os
import sys
import traceback
import argparse
from argparse import RawTextHelpFormatter
from phase_cli.cmd.open_console import phase_open_web
from phase_cli.cmd.update import phase_cli_update
from phase_cli.cmd.users.whoami import phase_users_whoami
from phase_cli.cmd.users.keyring import show_keyring_info
from phase_cli.cmd.users.logout import phase_cli_logout
from phase_cli.cmd.run import phase_run_inject
from phase_cli.cmd.init import phase_init
from phase_cli.cmd.auth import phase_auth
from phase_cli.cmd.secrets.list import phase_list_secrets
from phase_cli.cmd.secrets.get import phase_secrets_get
from phase_cli.cmd.secrets.export import phase_secrets_env_export
from phase_cli.cmd.secrets.import_env import phase_secrets_env_import
from phase_cli.cmd.secrets.delete import phase_secrets_delete
from phase_cli.cmd.secrets.create import phase_secrets_create
from phase_cli.cmd.secrets.update import phase_secrets_update

from phase_cli.utils.const import __version__
from phase_cli.utils.const import phaseASCii, description


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
        if "{auth,init,run,secrets,users,console,update}" in parts:
            parts = parts.replace("{auth,init,run,secrets,users,console,update}", "")
        return parts

class HelpfulParser(argparse.ArgumentParser):
    def __init__(self, *args, **kwargs):
        kwargs['formatter_class'] = CustomHelpFormatter
        super().__init__(*args, **kwargs)
        
    def error(self, message):
        print (description)
        print(phaseASCii)
        self.print_help()
        sys.exit(2)

    def add_subparsers(self, **kwargs):
        kwargs['title'] = 'Commands'
        return super(HelpfulParser, self).add_subparsers(**kwargs)

def main ():
    env_help = "Environment name eg. dev, staging, production"

    try:
        parser = HelpfulParser(prog='phase-cli', formatter_class=RawTextHelpFormatter)
        parser.add_argument('--version', '-v', action='version', version=__version__)
        
        # Create subparsers with title 'Available Commands:'
        subparsers = parser.add_subparsers(dest='command', required=True)

        # Auth command
        auth_parser = subparsers.add_parser('auth', help='💻 Authenticate with Phase')
        auth_parser.add_argument('--mode', choices=['token', 'webauth'], default='webauth', help='Mode of authentication. Default: webauth')

        # Init command
        init_parser = subparsers.add_parser('init', help='🔗 Link your project with your Phase app')

        # Run command
        run_parser = subparsers.add_parser('run', help='🚀 Run and inject secrets to your app')
        run_parser.add_argument('command_to_run', nargs=argparse.REMAINDER, help='Command to be run. Ex. phase run yarn dev')
        run_parser.add_argument('--env', type=str, help=env_help)

        # Secrets command
        secrets_parser = subparsers.add_parser('secrets', help='🗝️` Manage your secrets')
        secrets_subparsers = secrets_parser.add_subparsers(dest='secrets_command', required=True)

        # Secrets list command
        secrets_list_parser = secrets_subparsers.add_parser('list', help='📇 List all the secrets')
        secrets_list_parser.add_argument('--show', action='store_true', help='Return secrets uncensored')
        secrets_list_parser.add_argument('--env', type=str, help=env_help)
        secrets_list_parser.epilog = (
            "🔗 : Indicates that the secret value references another secret within the same environment.\n"
            "⛓️` : Indicates a cross-environment reference, where a secret in the current environment references a secret from another environment."
        )

        # Secrets get command
        secrets_get_parser = secrets_subparsers.add_parser('get', help='🔍 Get a specific secret by key')
        secrets_get_parser.add_argument('key', type=str, help='The key associated with the secret to fetch')
        secrets_get_parser.add_argument('--env', type=str, help=env_help)

        # Secrets create command
        secrets_create_parser = secrets_subparsers.add_parser(
            'create', 
            description='💳 Create a new secret. Optionally, you can provide the secret value via stdin.\n\nExample:\n  cat ~/.ssh/id_rsa | phase secrets create SSH_PRIVATE_KEY',
            help='💳 Create a new secret'
        )
        secrets_create_parser.add_argument(
            'key', 
            type=str, 
            nargs='?', 
            help='The key for the secret to be created. (Will be converted to uppercase.) If the value is not provided as an argument, it will be read from stdin.'
        )
        secrets_create_parser.add_argument('--env', type=str, help=env_help)

        # Secrets update command
        secrets_update_parser = secrets_subparsers.add_parser(
            'update', 
            description='📝 Update an existing secret. Optionally, you can provide the new secret value via stdin.\n\nExample:\n  cat ~/.ssh/id_ed25519 | phase secrets update SSH_PRIVATE_KEY',
            help='📝 Update an existing secret'
        )
        secrets_update_parser.add_argument(
            'key', 
            type=str, 
            help='The key associated with the secret to update. If the new value is not provided as an argument, it will be read from stdin.'
        )
        secrets_update_parser.add_argument('--env', type=str, help=env_help)

        # Secrets delete command
        secrets_delete_parser = secrets_subparsers.add_parser('delete', help='🗑️` Delete a secret')
        secrets_delete_parser.add_argument('keys', nargs='*', help='Keys to be deleted')
        secrets_delete_parser.add_argument('--env', type=str, help=env_help)

        # Secrets import command
        secrets_import_parser = secrets_subparsers.add_parser('import', help='📩 Import secrets from a .env file')
        secrets_import_parser.add_argument('env_file', type=str, help='The .env file to import')
        secrets_import_parser.add_argument('--env', type=str, help=env_help)

        # Secrets export command
        secrets_export_parser = secrets_subparsers.add_parser('export', help='🥡 Export secrets in a dotenv format')
        secrets_export_parser.add_argument('keys', nargs='*', help='List of keys separated by space', default=None)
        secrets_export_parser.add_argument('--env', type=str, help=env_help)

        # Users command
        users_parser = subparsers.add_parser('users', help='👥 Manage users and accounts')
        users_subparsers = users_parser.add_subparsers(dest='users_command', required=True)

        # Users whoami command
        whoami_parser = users_subparsers.add_parser('whoami', help='🙋 See details of the current user')

        # Users logout command
        logout_parser = users_subparsers.add_parser('logout', help='🏃 Logout from phase-cli')
        logout_parser.add_argument('--purge', action='store_true', help='Purge all local data')

        # Users keyring command
        keyring_parser = users_subparsers.add_parser('keyring', help='🔐 Display information about the Phase keyring')

        # Web command
        web_parser = subparsers.add_parser('console', help='🖥️` Open the Phase Console in your browser')

        # Check if the operating system is Linux before adding the update command
        if sys.platform == "linux":
            update_parser = subparsers.add_parser('update', help='🆙 Update the Phase CLI to the latest version')

        args = parser.parse_args()

        if args.command == 'auth':
            phase_auth(args.mode)
            sys.exit(0)
        elif args.command == 'init':
            phase_init()
        elif args.command == 'run':
            command = ' '.join(args.command_to_run)
            phase_run_inject(command, env_name=args.env)
        elif args.command == 'console':
            phase_open_web()
        elif args.command == 'update':
            phase_cli_update()
            sys.exit(0)
        elif args.command == 'users':
            if args.users_command == 'whoami':
                phase_users_whoami()
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
                phase_list_secrets(args.show, env_name=args.env)
            elif args.secrets_command == 'get':
                phase_secrets_get(args.key, env_name=args.env)  
            elif args.secrets_command == 'create':
                phase_secrets_create(args.key, env_name=args.env)
            elif args.secrets_command == 'delete':
                phase_secrets_delete(args.keys, env_name=args.env)  
            elif args.secrets_command == 'import':
                phase_secrets_env_import(args.env_file, env_name=args.env)
            elif args.secrets_command == 'export':
                phase_secrets_env_export(env_name=args.env, keys=args.keys)
            elif args.secrets_command == 'update':
                phase_secrets_update(args.key, env_name=args.env)
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
            print(str(e))
        sys.exit(1)

if __name__ == '__main__':
    main()
