import os

__version__ = "1.3.1"
__ph_version__ = "v1"

# Define paths to Phase configs
PHASE_ENV_CONFIG = '.phase.json' # Holds project and environment contexts in users repo, unique to each application.
PHASE_SECRETS_DIR = os.path.expanduser('~/.phase/secrets') # Holds local encrypted caches of secrets and environment variables, common to all projects.

PHASE_CLOUD_API_HOST = "https://api.phase.dev"