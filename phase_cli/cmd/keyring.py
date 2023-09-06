import keyring

def show_keyring_info():
    kr = keyring.get_keyring()
    print(f"Current keyring backend: {kr.__class__.__name__}")
    print("Supported keyring backends:")
    for backend in keyring.backend.get_all_keyring():
        print(f"- {backend.__class__.__name__}")