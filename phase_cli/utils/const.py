import os
import re

__version__ = "1.19.1"
__ph_version__ = "v1"

description = "Securely manage application secrets and environment variables with Phase."

phaseASCii = f"""
                     @@@             
              @@@@@@@@@@     
          @@@@@@@@@@@@@@@@
       P@@@@@&@@@?&@@&@@@@@P
     P@@@@#        @&@    @P@@@
    &@@@#         *@&      #@@@&
   &@@@5          &@?       5@@@&
  Y@@@#          ^@@         #@@@J
  #@@@7          B@5         7@@@#
  #@@@?         .@@.         ?@@@#
  @@@@&         5@G          &@@@7
   #@@@B        @@^         #@@@B
    B@@@@      .@#        7@@@@B
     @@@@@@    &.@       P@@@@@7
       @@@@@@@@@@@@@@@@@@@@@
          @@@@@@@@@@@@@@@
             @@@@@@@@
             @@@   
"""

SECRET_REF_REGEX = re.compile(r'\$\{([^}]+)\}')

# Define paths to Phase configs
PHASE_ENV_CONFIG = '.phase.json' # Holds project and environment contexts in users repo, unique to each application.

PHASE_SECRETS_DIR = os.path.expanduser('~/.phase/secrets') # Holds local encrypted caches of secrets and environment variables, common to all applications. (only if offline mode is enabled)
CONFIG_FILE = os.path.join(PHASE_SECRETS_DIR, 'config.json') # Holds local user account configurations

PHASE_CLOUD_API_HOST = "https://console.phase.dev"

pss_user_pattern = re.compile(r"^pss_user:v(\d+):([a-fA-F0-9]{64}):([a-fA-F0-9]{64}):([a-fA-F0-9]{64}):([a-fA-F0-9]{64})$")
pss_service_pattern = re.compile(r"^pss_service:v(\d+):([a-fA-F0-9]{64}):([a-fA-F0-9]{64}):([a-fA-F0-9]{64}):([a-fA-F0-9]{64})$")

cross_env_pattern = re.compile(r"\$\{(.+?)\.(.+?)\}")
local_ref_pattern = re.compile(r"\$\{([^.]+?)\}")

