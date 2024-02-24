class EnvironmentNotFoundException(Exception):
    def __init__(self, env_name):
        super().__init__(f"⚠️\u200A Warning: The environment '{env_name}' either does not exist or you do not have access to it.")
        