import os
import getpass
import keyring


def get_credentials():
    # Use environment variables if available
    phApp = os.getenv("PHASE_APP_ID")
    pss = os.getenv("PHASE_APP_SECRET")

    # If environment variables are not available, use the keyring
    if not phApp or not pss:
        try:
            phApp = keyring.get_password("phase", "phApp")
            pss = keyring.get_password("phase", "pss")
            return phApp, pss
        except keyring.errors.KeyringLocked:
            password = getpass.getpass("Please enter your keyring password: ")
            keyring.get_keyring().unlock(password)
            phApp = keyring.get_password("phase", "phApp")
            pss = keyring.get_password("phase", "pss")
            return phApp, pss
        except keyring.errors.KeyringError:
            print("System keyring is not available. Please set the PHASE_APP_ID and PHASE_APP_SECRET environment variables.")
            return None, None
    else:
        return phApp, pss
