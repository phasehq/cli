import os
import sys
import getpass
import keyring
from phase_cli.utils.misc import get_default_user_id, get_default_user_token

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
        if pss:
            return pss
        else:
            # If keyring returns None, try fetching the token from the config file
            return get_default_user_token()
    except keyring.errors.KeyringLocked:
        # Prompt user for the keyring password to unlock
        try:
            password = getpass.getpass("Please enter your keyring password: ")
            keyring.get_keyring().unlock(password)
            pss = keyring.get_password(service_name, "pss")
            if pss:
                return pss
            else:
                return get_default_user_token()
        except Exception as e:
            print(f"Failed to unlock keyring or retrieve token: {e}")
            sys.exit(1)
    except keyring.errors.KeyringError:
        # When system keyring is not available or on any keyring error, fetch from the config file
        return get_default_user_token()
    except Exception as e:
        print(f"An error occurred while trying to get credentials: {e}")
        sys.exit(1)
