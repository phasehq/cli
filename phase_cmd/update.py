import requests
import subprocess
import os

def phase_cli_update():
    # URL of the remote bash script
    url = "https://pkg.phase.dev/install.sh"
    
    try:
        # Fetch the script
        response = requests.get(url)
        response.raise_for_status()

        # Write the fetched script to a temporary file
        with open("temp_install.sh", "wb") as file:
            file.write(response.content)

        # Make the script executable
        os.chmod("temp_install.sh", 0o755)

        # Execute the script
        subprocess.call(["./temp_install.sh"])

        # Remove the temporary file after execution
        os.remove("temp_install.sh")
        
        print("Update completed successfully.")
    except requests.RequestException as e:
        print(f"Error fetching the update script: {e}")
    except subprocess.CalledProcessError:
        print("Error executing the update script.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")