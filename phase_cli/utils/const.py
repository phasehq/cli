import os
import re

__version__ = "1.21.2"
__ph_version__ = "v1"

description = (
    "Securely manage application secrets and environment variables with Phase."
)

phaseASCii = r"""
           /$$
          | $$
  /$$$$$$ | $$$$$$$   /$$$$$$   /$$$$$$$  /$$$$$$
 /$$__  $$| $$__  $$ |____  $$ /$$_____/ /$$__  $$
| $$  \ $$| $$  \ $$  /$$$$$$$|  $$$$$$ | $$$$$$$$
| $$  | $$| $$  | $$ /$$__  $$ \____  $$| $$_____/
| $$$$$$$/| $$  | $$|  $$$$$$$ /$$$$$$$/|  $$$$$$$
| $$____/ |__/  |__/ \_______/|_______/  \_______/
| $$
|__/
"""

SECRET_REF_REGEX = re.compile(r"\$\{(?!\{)([^}]+)\}")

# Define paths to Phase configs
PHASE_ENV_CONFIG = ".phase.json"  # Holds project and environment contexts in users repo, unique to each application.

PHASE_SECRETS_DIR = os.path.expanduser(
    "~/.phase/secrets"
)  # Holds local encrypted caches of secrets and environment variables, common to all applications. (only if offline mode is enabled)
CONFIG_FILE = os.path.join(
    PHASE_SECRETS_DIR, "config.json"
)  # Holds local user account configurations


PHASE_CLOUD_API_HOST = "https://console.phase.dev"

# AWS Config
AWS_DEFAULT_GLOBAL_STS_ENDPOINT = "https://sts.amazonaws.com"
AWS_DEFAULT_GLOBAL_STS_REGION = "us-east-1"

pss_user_pattern = re.compile(
    r"^pss_user:v(\d+):([a-fA-F0-9]{64}):([a-fA-F0-9]{64}):([a-fA-F0-9]{64}):([a-fA-F0-9]{64})$"
)
pss_service_pattern = re.compile(
    r"^pss_service:v(\d+):([a-fA-F0-9]{64}):([a-fA-F0-9]{64}):([a-fA-F0-9]{64}):([a-fA-F0-9]{64})$"
)

CROSS_APP_ENV_PATTERN = re.compile(r"\$\{(?!\{)(.+?)::(.+?)\.(.+?)\}")
CROSS_ENV_PATTERN = re.compile(r"\$\{(?!\{)(?![^{]*::)([^.]+?)\.(.+?)\}")
LOCAL_REF_PATTERN = re.compile(r"\$\{(?!\{)([^.]+?)\}")
