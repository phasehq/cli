import os
import json
import webbrowser
from phase_cli.utils.misc import get_default_user_host

def phase_open_console():
    """
    Open the Phase console in a web browser based on environment variables or local configuration.
    """
    try:
        url = get_default_user_host()
        webbrowser.open(url)
    except ValueError as e:
        print(f"Error opening Phase console: {e}")