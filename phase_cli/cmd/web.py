import os
import webbrowser

def phase_open_web():
    url = os.getenv('PHASE_HOST', 'https://console.phase.dev')
    webbrowser.open(url)