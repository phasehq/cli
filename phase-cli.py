import os
import sys
import argparse
from argparse import RawTextHelpFormatter
from cmd.web import phase_open_web
from cmd.keyring import show_keyring_info
from utils.ascii import phaseASCii
from cmd.phase import phase_run_inject, phase_list_secrets, phase_cli_logout, phase_secrets_env_export, phase_secrets_env_import, phase_secrets_delete, phase_secrets_create, phase_init, phase_auth
from utils.keyring import get_credentials

__version__ = "0.2.2b"

def print_phase_cli_version():
    print(f"Version: {__version__}")

def print_phase_cli_version_only():
    print(f"{__version__}")


class HelpfulParser(argparse.ArgumentParser):
    def error(self, message):
        self.print_help()
        sys.exit(2)

if __name__ == '__main__':

    try:
        parser = HelpfulParser(prog='phase-cli', description=phaseASCii, formatter_class=RawTextHelpFormatter)

        parser.add_argument('--version', '-v', action='version', version=__version__)
        subparsers = parser.add_subparsers(dest='command', required=True)

        # Auth command
        auth_parser = subparsers.add_parser('auth', help='Authenticate with Phase')

        # Init command
        init_parser = subparsers.add_parser('init', help='Link your local repo to a Phase app environment')

        # Run command
        run_parser = subparsers.add_parser('run', help='Automatically run and inject environment variables to your application')
        run_parser.add_argument('run <command>', nargs=argparse.REMAINDER, help='Command to be run. Ex. phase run yarn dev')

        # Secrets command
        secrets_parser = subparsers.add_parser('secrets', help='Manage your secrets')
        secrets_subparsers = secrets_parser.add_subparsers(dest='secrets_command', required=True)

        # Secrets list command
        secrets_list_parser = secrets_subparsers.add_parser('list', help='List all the secrets')
        secrets_list_parser.add_argument('--show', action='store_true', help='Show uncensored secrets')

        # Secrets create command
        secrets_create_parser = secrets_subparsers.add_parser('create', help='Create a new secret')
        secrets_create_parser.add_argument('--env', type=str, help='Import secrets from a .env file')

        # Secrets delete command
        secrets_delete_parser = secrets_subparsers.add_parser('delete', help='Delete a secret')
        secrets_delete_parser.add_argument('keys', nargs='*', help='Keys to be deleted')

        # Secrets import command
        secrets_import_parser = secrets_subparsers.add_parser('import', help='Import secrets from a .env file')
        secrets_import_parser.add_argument('env_file', type=str, help='The .env file to import')

        # Secrets export command
        secrets_export_parser = secrets_subparsers.add_parser('export', help='Export secrets to a .env file')

        # Logout command
        logout_parser = subparsers.add_parser('logout', help='Logout from phase-cli and delete local credentials')
        logout_parser.add_argument('--purge', action='store_true', help='Purge all local data')

        # Web command
        web_parser = subparsers.add_parser('web', help='Open the Phase Console in the default web browser')

        # Keyring command
        keyring_parser = subparsers.add_parser('keyring', help='Display information about the phase keyring')

        args = parser.parse_args()

        if args.command == 'auth':
            phase_auth()
            sys.exit(0)

        phApp, pss = get_credentials()
        if not phApp or not pss:
            print("No accounts found. Please run 'phase auth' or supply PHASE_APP_ID & PHASE_APP_SECRET")
            sys.exit(1)

        if args.command == 'init':
            phase_init()
        elif args.command == 'run':
            command = ' '.join(args.run_command)
            phase_run_inject(command)
        elif args.command == 'logout':
            phase_cli_logout(args.purge)
        elif args.command == 'web':
            phase_open_web()
        elif args.command == 'keyring':
            show_keyring_info()
        elif args.command == 'secrets':
            if args.secrets_command == 'list':
                phase_list_secrets(phApp, pss, args.show)  
            elif args.secrets_command == 'create':
                phase_secrets_create() 
            elif args.secrets_command == 'delete':
                phase_secrets_delete(args.keys)  
            elif args.secrets_command == 'import':
                phase_secrets_env_import(args.env_file)
            elif args.secrets_command == 'export':
                phase_secrets_env_export()
        else:
            print("Unknown command: " + ' '.join(args.command))
            parser.print_help()
            sys.exit(1)
    except KeyboardInterrupt:
        print("\nStopping Phase.")
        sys.exit(0)