import os
import re
__version__ = "1.11.3"
__ph_version__ = "v1"

description = "Securely manage and sync environment variables with Phase."

phaseASCii = f"""
         ⢠⠔⠋⣳⣖⠚⣲⢖⠙⠳⡄                          
        ⡴⠉⢀⡼⠃⢘⣞⠁⠙⡆ ⠘⡆                         
      ⢀⡜⠁⢠⠞ ⢠⠞⠸⡆ ⠹⡄ ⠹⡄                        
     ⢀⠞ ⢠⠏ ⣠⠏  ⢳  ⢳  ⢧                        
    ⢠⠎ ⣠⠏ ⣰⠃   ⠈⣇ ⠘⡇ ⠘⡆                       
   ⢠⠏ ⣰⠇ ⣰⠃     ⢺⡀ ⢹  ⢽                       
  ⢠⠏ ⣰⠃ ⣰⠃       ⣇ ⠈⣇ ⠘⡇                      
 ⢠⠏ ⢰⠃ ⣰⠃        ⢸⡀ ⢹⡀ ⢹                      
⢠⠏ ⢰⠃ ⣰⠃          ⣇ ⠈⣇ ⠈⡇                     
⠛⠒⠚⠛⠒⠓⠚⠒⠒⠓⠒⠓⠚⠒⠓⠚⠒⠓⢻⡒⠒⢻⡒⠒⢻⡒⠒⠒⠒⠒⠒⠒⠒⠒⠒⣲⠒⠒⣲⠒⠒⡲    
                   ⢧  ⢧ ⠈⣇        ⢠⠇ ⣰⠃ ⣰⠃    
                   ⠘⡆ ⠘⡆ ⠸⡄      ⣠⠇ ⣰⠃ ⣴⠃     
                    ⠹⡄ ⠹⡄ ⠹⡄    ⡴⠃⢀⡼⠁⢀⡼⠁      
                     ⠙⣆ ⠙⣆ ⠹⣄ ⣠⠎⠁⣠⠞ ⡤⠏        
                      ⠈⠳⢤⣈⣳⣤⣼⣹⢥⣰⣋⡥⡴⠊⠁         
"""

# Define paths to Phase configs
PHASE_ENV_CONFIG = '.phase.json' # Holds project and environment contexts in users repo, unique to each application.

PHASE_SECRETS_DIR = os.path.expanduser('~/.phase/secrets') # Holds local encrypted caches of secrets and environment variables, common to all applications. (only if offline mode is enabled)
CONFIG_FILE = os.path.join(PHASE_SECRETS_DIR, 'config.json') # Holds local user account configurations

PHASE_CLOUD_API_HOST = "https://console.phase.dev"

pss_user_pattern = re.compile(r"^pss_user:v(\d+):([a-fA-F0-9]{64}):([a-fA-F0-9]{64}):([a-fA-F0-9]{64}):([a-fA-F0-9]{64})$")
pss_service_pattern = re.compile(r"^pss_service:v(\d+):([a-fA-F0-9]{64}):([a-fA-F0-9]{64}):([a-fA-F0-9]{64}):([a-fA-F0-9]{64})$")

cross_env_pattern = re.compile(r"\$\{(.+?)\.(.+?)\}")
local_ref_pattern = re.compile(r"\$\{([^.]+?)\}")

