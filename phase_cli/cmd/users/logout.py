import os
import sys
import shutil
import keyring
from phase_cli.utils.const import PHASE_SECRETS_DIR
from phase_cli.utils.misc import get_default_user_id

def phase_cli_logout(purge=False):
    if purge:
        all_user_ids = get_default_user_id(all_ids=True)
        for user_id in all_user_ids:
            keyring.delete_password(f"phase-cli-user-{user_id}", "pss")

        # Delete PHASE_SECRETS_DIR if it exists
        if os.path.exists(PHASE_SECRETS_DIR):
            shutil.rmtree(PHASE_SECRETS_DIR)
            print("Logged out and purged all local data.")
        else:
            print("No local data found to purge.")

    else:
        # For the default user
        pss = keyring.get_password("phase", "pss")
        if not pss:
            print("No configuration found. Please run 'phase auth' to set up your configuration.")
            sys.exit(1)
        keyring.delete_password("phase", "pss")
        print("Logged out successfully.")