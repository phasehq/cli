import os
import webbrowser
from phase_cli.utils.const import PHASE_CLOUD_API_HOST

def phase_open_web():
    url = os.getenv('PHASE_HOST', PHASE_CLOUD_API_HOST)
    webbrowser.open(url)