import os
import getpass
import keyring
from phase_cli.utils.misc import get_default_user_id

def get_credentials():
    # Fetch user ID for keyring service name
    default_user_id = get_default_user_id()
    service_name = f"phase-cli-user-{default_user_id}"

    # Use environment variables if available
    pss = os.getenv("PHASE_APP_SECRET")

    # If environment variables are not available, use the keyring
    if not pss:
        try:
            pss = keyring.get_password(service_name, "pss")
            return pss
        except keyring.errors.KeyringLocked:
            password = getpass.getpass("Please enter your keyring password: ")
            keyring.get_keyring().unlock(password)
            pss = keyring.get_password(service_name, "pss")
            return pss
        except keyring.errors.KeyringError:
            print("System keyring is not available. Please set the PHASE_APP_SECRET environment variable.")
            return None
    else:
        return pss