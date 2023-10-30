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
from phase_cli.utils.misc import open_browser, validate_url, print_phase_links
from phase_cli.utils.crypto import CryptoUtils
from phase_cli.utils.phase_io import Phase
from phase_cli.utils.const import PHASE_SECRETS_DIR, PHASE_CLOUD_API_HOST


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


def phase_auth(mode="webauth"):
    """
    Handles authentication for the Phase CLI using either web-based or token-based authentication.

    For webauth:
        - Start an http server on http://localhost<random_port>
        - Spin up ephemeral X25519 keypair - used to secure user's personal access token in flight during authentication for added protection
        - Fetch local username and hostname - used to name users personal access tokens in the Phase Console
        - Open the web browser on the PHASE_API_HOST/webauth/b64(port-X25519_public_key-personal_access_token_name)
        - Wait for the Phase Console to hit a POST request to http://localhost<random_port> with the encrypted payload containing (user_email, personal_access_token)
        - Decrypt the payload via CryptoUtils.decrypt_asymmetric(pss_encrypted, private_key.hex(), public_key.hex()) and write it to keyring

    Args:
    - mode (str): The mode of authentication to use. Default is "webauth". Can be either "webauth" or "token".

    Returns:
    None
    """
    server = None
    try:
        # Choose the authentication mode: webauth (default) or token-based.
        if mode == 'token':
            # Manual token-based authentication
            phase_instance_type = questionary.select(
                'Choose your Phase instance type:',
                choices=['☁️  Phase Cloud', '🛠️  Self Hosted']
            ).ask()

            if not phase_instance_type:
                print("\nExiting phase...")
                return

            if phase_instance_type == '🛠️  Self Hosted':
                PHASE_API_HOST = questionary.text("Please enter your host (URL eg. https://example.com/path):").ask()
                if not PHASE_API_HOST:
                    print("\nExiting phase...")
                    return
            else:
                PHASE_API_HOST = PHASE_CLOUD_API_HOST

            user_email = questionary.text("Please enter your email:").ask()
            if not user_email:
                print("\nExiting phase...")
                return

            personal_access_token = getpass.getpass("Please enter Phase user token (hidden): ")
            if not personal_access_token:
                print("\nExiting phase...")
                return

            # Authenticate using the provided token
            phase = Phase(init=False, pss=personal_access_token, host=PHASE_API_HOST)
            result = phase.auth()

        else:
            # Web-based authentication
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
                print("Invalid URL. Please ensure you include the scheme (e.g., https) and domain. Keep in mind, path and port are optional.")
                return

            # Start an HTTP web server at a random port and spin up the keys.
            port = random.randint(8000, 20000)
            server = start_server(port, PHASE_API_HOST)
            public_key, private_key = CryptoUtils.random_key_pair()

            # Fetch local username and hostname. To be used as title for personal access token
            username = os.getlogin()
            hostname = platform.node()
            personal_access_token_name = f"{username}@{hostname}"

            # Prepare the string to be encoded
            raw_data = f"{port}-{public_key.hex()}-{personal_access_token_name}"
            encoded_data = base64.b64encode(raw_data.encode()).decode()

            # Print the link in the console
            print(f"Please authenticate via the Phase Console: {PHASE_API_HOST}/webauth/{encoded_data}")

            # Open the URL silently
            open_browser(f"{PHASE_API_HOST}/webauth/{encoded_data}")

            # Wait for the POST request from the web UI.
            while not server.received_data:
                time.sleep(1)

            # Extract credentials from the received data
            user_email = server.received_data.get('email')
            pss_encrypted = server.received_data.get('pss')

            if not (user_email and pss_encrypted):
                raise ValueError("Email or pss not received from the web UI.")

            # Decrypt user's Phase personal access token from the webauth payload
            decrypted_personal_access_token = CryptoUtils.decrypt_asymmetric(pss_encrypted, private_key.hex(), public_key.hex())

            # Authenticate with the decrypted pss
            phase = Phase(init=False, pss=decrypted_personal_access_token, host=PHASE_API_HOST)
            personal_access_token=decrypted_personal_access_token
            result = phase.auth()

        if result == "Success":
            user_data = phase.init()
            user_id = user_data["user_id"]
            offline_enabled = user_data["offline_enabled"]
            wrapped_key_share = None if not offline_enabled else user_data["wrapped_key_share"]

            # Save the credentials in the Phase keyring
            keyring.set_password(f"phase-cli-user-{user_id}", "pss", personal_access_token)

            # Prepare the data to be saved in config.json
            config_data = {
                "default-user": user_id,
                "phase-users": [
                    {
                        "email": user_email,
                        "host": PHASE_API_HOST,
                        "id": user_id,
                        "wrapped_key_share": wrapped_key_share
                    }
                ]
            }

            # Save the data in PHASE_SECRETS_DIR/config.json
            os.makedirs(PHASE_SECRETS_DIR, exist_ok=True)
            with open(os.path.join(PHASE_SECRETS_DIR, 'config.json'), 'w') as f:
                json.dump(config_data, f, indent=4)

            print("\033[1;32m✅ Authentication successful. Credentials saved in the Phase keyring.\033[0m")
            print("\033[1;36m🎉 Welcome to Phase CLI!\033[0m\n")
            print_phase_links()

        else:
            print("Failed to authenticate with the provided credentials.")
    except KeyboardInterrupt:
        print("\nExiting phase...")
    except Exception as e:
        print(f"An error occurred: {e}")
        sys.exit(1)
    finally:
        if server:
            server.shutdown()