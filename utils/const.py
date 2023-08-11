import os

# Define paths to Phase configs
PHASE_ENV_CONFIG = '.phase.json' # Holds project and environment contexts in users repo, unique to each application.
PHASE_SECRETS_DIR = os.path.expanduser('~/.phase/secrets') # Holds local encrypted caches of secrets and environment variables, common to all projects.