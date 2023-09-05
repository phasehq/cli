import os

__version__ = "1.5.3"
__ph_version__ = "v1"

description = "Securely manage and sync environment variables with Phase."

phaseASCii = f"""
         :@tX88%%:                   
        ;X;%;@%8X@;               
      ;Xt%;S8:;;t%S    
      ;SXStS@.;t8@:;.  
    ;@:t;S8  ;@.%.;8:  
    :X:S%88    S.88t:. 
  :X:%%88     :S:t.t8t
.@8X888@88888888X8.%8X8888888X8.S88: 
                ;t;X8;      ;XS:%X;
                :@:8@X.     XXS%S8    
                 8XX:@8S  .X%88X;
                  .@:XX88:8Xt8:     
                     :%88@S8:                  
    """

# Define paths to Phase configs
PHASE_ENV_CONFIG = '.phase.json' # Holds project and environment contexts in users repo, unique to each application.
PHASE_SECRETS_DIR = os.path.expanduser('~/.phase/secrets') # Holds local encrypted caches of secrets and environment variables, common to all projects.

PHASE_CLOUD_API_HOST = "https://api.phase.dev"