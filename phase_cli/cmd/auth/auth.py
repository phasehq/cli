import json
import os
import platform
import keyring
import sys
import http.server
import getpass
import socketserver
import threading
import base64
import time, random
import questionary
from phase_cli.utils.misc import open_browser, validate_url
from phase_cli.utils.crypto import CryptoUtils
from phase_cli.utils.phase_io import Phase
from phase_cli.utils.const import PHASE_SECRETS_DIR, PHASE_CLOUD_API_HOST
from phase_cli.cmd.auth.aws import perform_aws_iam_auth
from rich.console import Console

class SimpleHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    """
    A custom HTTP request handler that overrides the default behavior to handle POST requests.
    """
    def do_POST(self):
        """
        Handle incoming POST requests.
        """
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        try:
            data = json.loads(post_data)
            self.server.received_data = data
            self.send_response(200)
            self.end_headers()
        except json.JSONDecodeError:
            self.send_response(400)
            self.end_headers()      


def start_server(port, PHASE_API_HOST):
    """
    Starts an HTTP server on a specified port.

    Args:
    - port (int): The port number on which the server should run.
    - PHASE_API_HOST (str): The API host for setting CORS headers.

    Returns:
    - httpd (socketserver.TCPServer): The HTTP server instance.
    """
    class QuietHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
        def log_message(self, format, *args):
            # Do not log anything to keep the console quiet.
            pass
        
        def do_OPTIONS(self):           
            self.send_response(200, "ok")       
            self.send_header('Access-Control-Allow-Origin', PHASE_API_HOST)
            #self.send_header('Access-Control-Allow-Origin', 'https://localhost')
            self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
            self.send_header("Access-Control-Allow-Headers", "X-Requested-With, Content-type")
            self.end_headers()
        
        def do_POST(self):
            # Here we'll handle the POST request. 
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            
            # Assuming the client sends JSON data, parse it.
            try:
                data = json.loads(post_data)
                self.server.received_data = data
                self.send_response(200)
                self.send_header("Content-type", "application/json")
                self.send_header('Access-Control-Allow-Origin', PHASE_API_HOST)  
                #self.send_header('Access-Control-Allow-Origin', 'https://localhost')
                self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
                self.send_header("Access-Control-Allow-Headers", "X-Requested-With, Content-type")
                self.end_headers()
                self.wfile.write(json.dumps({"status": "Success: CLI authentication complete"}).encode('utf-8'))
            except json.JSONDecodeError:
                self.send_response(400)
                self.send_header("Content-type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"error": "Invalid JSON"}).encode('utf-8'))

    handler = QuietHTTPRequestHandler
    httpd = socketserver.TCPServer(("", port), handler)
    httpd.received_data = None

    thread = threading.Thread(target=httpd.serve_forever)
    thread.start()

    return httpd


def phase_auth(mode="webauth", service_account_id=None, ttl=None, no_store=False):
    """
    Handles authentication for the Phase CLI using web-based, token-based, or AWS IAM authentication.

    If a user is already authenticated, the function will notify the user of their logged-in status and provide instructions for logging out and logging back in.

    For webauth:
        - Checks if the user is already authenticated.
        - If authenticated, displays the user's email and provides instructions for logging out and logging back in.
        - Otherwise, starts an http server on http://localhost<random_port>.
        - Spins up an ephemeral X25519 keypair to secure the user's personal access token during authentication.
        - Fetches the local username and hostname to name the user's personal access tokens in the Phase Console.
        - Opens the web browser on the PHASE_API_HOST/webauth/b64(port-X25519_public_key-personal_access_token_name).
        - Waits for the Phase Console to send a POST request to http://localhost<random_port> with the encrypted payload containing the user_email and personal_access_token.
        - Decrypts the payload using CryptoUtils.decrypt_asymmetric(personal_access_token_encrypted, private_key.hex(), public_key.hex()).
        - Validates the credentials and writes them to the keyring.

    For token:
        - Asks the user for their email and personal access token.
        - Validates the credentials and writes them to the keyring.

    For aws-iam:
        - Uses AWS IAM credentials to authenticate with Phase.
        - Requires a service account ID to be provided.
        - Signs an AWS STS GetCallerIdentity request and sends it to Phase for verification.
        - Receives a Phase token in response and stores it in the keyring.

    Args:
        - mode (str): The mode of authentication to use. Default is "webauth". Can be either "webauth", "token", or "aws-iam".
        - service_account_id (str): Required for aws-iam mode. The service account ID to authenticate with.
        - ttl (int): Optional for aws-iam mode. Token TTL in seconds.

    Returns:
        None
    """
    # Create a console object for logging warnings and errors to stderr
    console = Console(stderr=True)

    server = None
    try:
        # Choose the authentication mode: webauth (default), token-based, or aws-iam.
        if mode == 'aws-iam':
            # AWS IAM authentication
            if not service_account_id:
                console.log("Error: --service-account-id is required when using --mode aws-iam")
                sys.exit(2)
            
            # Check if PHASE_HOST environment variable is set for headless operation
            PHASE_API_HOST = os.getenv("PHASE_HOST")
            
            if PHASE_API_HOST:
                console.log(f"Using PHASE_HOST environment variable: {PHASE_API_HOST}")
            else:
                # Interactive mode: ask user to choose instance type
                phase_instance_type = questionary.select(
                    'Choose your Phase instance type:',
                    choices=['☁️  Phase Cloud', '🛠️  Self Hosted']
                ).ask()

                if not phase_instance_type:
                    console.log("\nExiting phase...")
                    return

                if phase_instance_type == '🛠️  Self Hosted':
                    PHASE_API_HOST = questionary.text("Please enter your host (URL eg. https://example.com/path):").ask()
                    if not PHASE_API_HOST:
                        console.log("\nExiting phase...")
                        return
                else:
                    PHASE_API_HOST = PHASE_CLOUD_API_HOST

            # Perform AWS IAM authentication
            try:
                console.log("Authenticating with AWS IAM credentials...")
                aws_result = perform_aws_iam_auth(host=PHASE_API_HOST, service_account_id=service_account_id, ttl=ttl)
                
                # Extract the token from the AWS auth response
                auth_data = aws_result.get("authentication", {})
                auth_token = auth_data.get("token")
                
                if not auth_token:
                    raise ValueError("No token received from AWS IAM authentication")
                
                console.log("AWS IAM authentication successful")
                
                # If user requested no-store, print raw result and exit early
                if no_store:
                    print(json.dumps(aws_result, indent=4))
                    return
                
                # Validate the token with Phase API by initializing Phase client
                phase = Phase(init=False, pss=auth_token, host=PHASE_API_HOST)
                result = phase.auth()
                user_email = None  # Service accounts don't have emails
                
            except Exception as e:
                console.log(f"AWS IAM authentication failed: {e}")
                return
            
        elif mode == 'token':
            # Manual token-based authentication
            # Check if PHASE_HOST environment variable is set for headless operation
            PHASE_API_HOST = os.getenv("PHASE_HOST")
            
            if PHASE_API_HOST:
                console.log(f"Using PHASE_HOST environment variable: {PHASE_API_HOST}")
            else:
                # Interactive mode: ask user to choose instance type
                phase_instance_type = questionary.select(
                    'Choose your Phase instance type:',
                    choices=['☁️  Phase Cloud', '🛠️  Self Hosted']
                ).ask()

                if not phase_instance_type:
                    console.log("\nExiting phase...")
                    return

                if phase_instance_type == '🛠️  Self Hosted':
                    PHASE_API_HOST = questionary.text("Please enter your host (URL eg. https://example.com/path):").ask()
                    if not PHASE_API_HOST:
                        console.log("\nExiting phase...")
                        sys.exit(2)
                        return
                else:
                    PHASE_API_HOST = PHASE_CLOUD_API_HOST

            auth_token = getpass.getpass("Please enter Personal Access Token (PAT) or a Service Account Token (hidden): ")
            if not auth_token:
                console.log("\nExiting phase...")
                return
            
            # Check if it's a service token (they start with 'pss_service:')
            is_service_token = auth_token.startswith('pss_service:')
            is_personal_token = auth_token.startswith('pss_user:')
            user_email = None
            
            if is_personal_token:
                # Personal Access Tokens require an email
                user_email = questionary.text("Please enter your email:").ask()
                if not user_email:
                    console.log("\nExiting phase...")
                    return
            elif not is_service_token and not is_personal_token:
                # Unknown token format, might be an older format - ask for email to be safe
                user_email = questionary.text("Please enter your email:").ask()
                if not user_email:
                    console.log("\nExiting phase...")
                    return

            # Authenticate using the provided token
            phase = Phase(init=False, pss=auth_token, host=PHASE_API_HOST)
            result = phase.auth()

        else:
            # Web-based authentication
            # Check if PHASE_HOST environment variable is set for headless operation
            PHASE_API_HOST = os.getenv("PHASE_HOST")
            
            if PHASE_API_HOST:
                console.log(f"Using PHASE_HOST environment variable: {PHASE_API_HOST}")
            else:
                # Interactive mode: ask user to choose instance type
                phase_instance_type = questionary.select(
                    'Choose your Phase instance type:',
                    choices=['☁️  Phase Cloud', '🛠️  Self Hosted']
                ).ask()

                if not phase_instance_type:
                    return

                if phase_instance_type == '🛠️  Self Hosted':
                    PHASE_API_HOST = questionary.text("Please enter your host (URL eg. https://example.com/path):").ask()
                else:
                    PHASE_API_HOST = PHASE_CLOUD_API_HOST

                if not PHASE_API_HOST:
                    return
            
            if not validate_url(PHASE_API_HOST):
                console.log("Invalid URL. Please ensure you include the scheme (e.g., https) and domain. Keep in mind, path and port are optional.")
                sys.exit(2)
                return

            # Start an HTTP web server at a random port and spin up the keys.
            port = random.randint(8000, 20000)
            server = start_server(port, PHASE_API_HOST)
            public_key, private_key = CryptoUtils.random_key_pair()

            # Fetch local username and hostname. To be used as title for personal access token
            username = getpass.getuser()
            hostname = platform.node()
            personal_access_token_name = f"{username}@{hostname}"

            # Prepare the string to be encoded
            raw_data = f"{port}-{public_key.hex()}-{personal_access_token_name}"
            encoded_data = base64.b64encode(raw_data.encode()).decode()

            # Print the link in the console
            console.print(f"Please authenticate via the Phase Console: {PHASE_API_HOST}/webauth/{encoded_data}")

            # Open the URL silently
            open_browser(f"{PHASE_API_HOST}/webauth/{encoded_data}")

            # Wait for the POST request from the web UI.
            while not server.received_data:
                time.sleep(1)

            # Extract credentials from the received data
            user_email_encrypted = server.received_data.get('email')
            personal_access_token_encrypted = server.received_data.get('pss')

            if not (user_email_encrypted and personal_access_token_encrypted):
                raise ValueError("Webauth unsuccessful: User email or personal access token missing.")

            # Decrypt user's Phase personal access token from the webauth payload
            decrypted_personal_access_token = CryptoUtils.decrypt_asymmetric(personal_access_token_encrypted, private_key.hex(), public_key.hex())
            user_email = CryptoUtils.decrypt_asymmetric(user_email_encrypted, private_key.hex(), public_key.hex())

            # Authenticate with the decrypted pss
            phase = Phase(init=False, pss=decrypted_personal_access_token, host=PHASE_API_HOST)
            auth_token = decrypted_personal_access_token
            result = phase.auth()

        if result == "Success":
            user_data = phase.init()
            # Handle both user accounts (PATs) and service accounts (service tokens)
            account_id = user_data.get("user_id") or user_data.get("account_id")
            if not account_id:
                raise ValueError("Neither user_id nor account_id found in authentication response")
            
            offline_enabled = user_data["offline_enabled"]
            wrapped_key_share = None if not offline_enabled else user_data["wrapped_key_share"]

            # Note: Phase Console <v2.14.0 doesn't return Organization name and id
            organization_id = user_data["organisation"]["id"] if 'organisation' in user_data and user_data['organisation'] else None
            organization_name = user_data["organisation"]["name"] if 'organisation' in user_data and user_data['organisation'] else None

            # Save the credentials in the Phase keyring
            try:
                keyring.set_password(f"phase-cli-user-{account_id}", "pss", auth_token)
                token_saved_in_keyring = True
            except Exception as e:
                if os.getenv("PHASE_DEBUG") == "True":
                    console.log(f"Failed to save token in keyring: {e}")
                token_saved_in_keyring = False

            # Load existing config or initialize a new one
            config_file_path = os.path.join(PHASE_SECRETS_DIR, 'config.json')
            if os.path.exists(config_file_path):
                with open(config_file_path, 'r') as f:
                    config_data = json.load(f)
            else:
                config_data = {"default-user": None, "phase-users": []}

            # Update the config_data with the new user, ensuring no duplicates
            existing_users = {user['id']: user for user in config_data["phase-users"]}
            user_data_config = {
                "host": PHASE_API_HOST,
                "id": account_id,
                "organization_id": organization_id,
                "organization_name": organization_name,
                "wrapped_key_share": wrapped_key_share
            }
            # Only add email if it exists (service accounts may not have one)
            if user_email:
                user_data_config["email"] = user_email
            # If saving to keyring failed, save the token in the config_data
            if not token_saved_in_keyring:
                user_data_config["token"] = auth_token
            existing_users[account_id] = user_data_config
            config_data["phase-users"] = list(existing_users.values())

            # Set the latest user as the default user
            config_data["default-user"] = account_id

            # Save the updated configuration
            os.makedirs(PHASE_SECRETS_DIR, exist_ok=True)
            with open(config_file_path, 'w') as f:
                json.dump(config_data, f, indent=4)

            if token_saved_in_keyring:
                console.print("[bold green]✅ Authentication successful.[/bold green]")
            else:
                console.print("[bold green]✅ Authentication successful.[/bold green]")

        else:
            console.log("Failed to authenticate with the provided credentials.")
    except KeyboardInterrupt:
        console.log("\nExiting phase...")
    except Exception as e:
        console.log(f"An error occurred: {e}")
        sys.exit(1)
    finally:
        if server:
            server.shutdown()
