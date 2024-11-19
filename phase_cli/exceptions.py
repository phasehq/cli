class EnvironmentNotFoundException(Exception):
    def __init__(self, env_name):
        super().__init__(f"⚠️\u200A Warning: The environment '{env_name}' either does not exist or you do not have access to it.")

class OverrideNotFoundException(Exception):
    def __init__(self, key):
        super().__init__(f"No override exists for this secret. To set one, run: phase secrets update {key} --override")

# Network

class AuthorizationError(Exception):
    """Raised when user is not authorized to perform an action"""
    pass

class APIError(Exception):
    """Raised when API returns an error response"""
    pass

class SSLError(Exception):
    """Raised when there are SSL verification issues"""
    pass