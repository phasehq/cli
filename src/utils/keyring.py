import os
import sys
import getpass
import keyring
from src.utils.misc import get_default_user_id

def get_credentials():
    # Use environment variables if available
    pss = os.getenv("PHASE_SERVICE_TOKEN")

    if pss:
        return pss

    # Fetch user ID for keyring service name
    default_user_id = get_default_user_id()
    service_name = f"phase-cli-user-{default_user_id}"

    try:
        pss = keyring.get_password(service_name, "pss")
        if not pss:
            print("No configuration found. Please run 'phase auth' to set up your configuration.")
            sys.exit(1)
        return pss
    except keyring.errors.KeyringLocked:
        password = getpass.getpass("Please enter your keyring password: ")
        keyring.get_keyring().unlock(password)
        pss = keyring.get_password(service_name, "pss")
        return pss
    except keyring.errors.KeyringError:
        print("System keyring is not available. Please set the PHASE_APP_SECRET environment variable.")
        sys.exit(1)
