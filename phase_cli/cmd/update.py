import requests
import subprocess
import os
import sys
from rich.console import Console

def phase_cli_update():
    # URL of the remote bash script
    url = "https://pkg.phase.dev/install.sh"
    console = Console()
    
    try:
        # Fetch the script
        response = requests.get(url)
        response.raise_for_status()

        # Write the fetched script to a temporary file
        with open("temp_install.sh", "wb") as file:
            file.write(response.content)

        # Make the script executable
        os.chmod("temp_install.sh", 0o755)

        # Execute the script with clean environment to avoid library conflicts
        clean_env = os.environ.copy()
        # Remove any LD_LIBRARY_PATH that might point to bundled libraries
        clean_env.pop('LD_LIBRARY_PATH', None)
        
        # Use subprocess.run instead of subprocess.call for better error handling
        result = subprocess.run(["./temp_install.sh"], env=clean_env, capture_output=True, text=True)
        
        # Check if the script execution was successful
        if result.returncode != 0:
            console.log(f"[bold red]Error:[/] Update script failed with exit code {result.returncode}")
            if result.stderr:
                console.log(f"[bold red]Error details:[/] {result.stderr.strip()}")
            if result.stdout:
                console.log(f"[bold yellow]Output:[/] {result.stdout.strip()}")
            sys.exit(1)

        # Remove the temporary file after execution
        os.remove("temp_install.sh")
        
        console.log("[bold green]✅ Update completed successfully.[/]")
        
    except requests.RequestException as e:
        console.log(f"[bold red]Error:[/] Failed to fetch the update script: {e}")
        sys.exit(1)
    except FileNotFoundError:
        console.log("[bold red]Error:[/] Failed to create or execute the temporary install script")
        sys.exit(1)
    except PermissionError as e:
        console.log(f"[bold red]Error:[/] Permission denied: {e}")
        console.log("[bold yellow]Tip:[/] Try running with sudo privileges or check file permissions")
        sys.exit(1)
    except OSError as e:
        console.log(f"[bold red]Error:[/] OS error occurred: {e}")
        sys.exit(1)
    except Exception as e:
        console.log(f"[bold red]Error:[/] An unexpected error occurred: {e}")
        sys.exit(1)
    finally:
        # Ensure cleanup even if an error occurs
        if os.path.exists("temp_install.sh"):
            try:
                os.remove("temp_install.sh")
            except OSError:
                pass
