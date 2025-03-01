import sys
import webbrowser

def phase_open_docs():
    """Opens the Phase documentation in a web browser"""
    try:
        url = "https://docs.phase.dev/cli/commands"
        webbrowser.open(url)
    except Exception as e:
        print(f"Error opening Phase documentation: {e}")
        sys.exit(1)