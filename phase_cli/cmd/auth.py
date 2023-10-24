import json
import os
import platform
import keyring
import sys
import http.server
import socketserver
import threading
import webbrowser
import time, random
import questionary
from phase_cli.utils.crypto import CryptoUtils
from phase_cli.utils.phase_io import Phase
from phase_cli.utils.const import PHASE_SECRETS_DIR, PHASE_CLOUD_API_HOST


class SimpleHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    # Override do_POST method to handle incoming POST requests
    def do_POST(self):
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


def start_server(port):
    class QuietHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
        def log_message(self, format, *args):
            # Do not log anything to keep the console quiet.
            pass
        
        def do_OPTIONS(self):           
            self.send_response(200, "ok")       
            self.send_header('Access-Control-Allow-Origin', '*')  # You should limit this to known domains
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
                self.send_header('Access-Control-Allow-Origin', '*')  # You should limit this to known domains
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


# Takes Phase credentials from user and stored them securely in the system keyring
def phase_auth():
    # 1. Start an HTTP web server at a random port.
    port = random.randint(8000, 9000)
    server = start_server(port)

    public_key, private_key = CryptoUtils.random_key_pair()

    try:
        # 2. Ask the user for the type of Phase instance.
        phase_instance_type = questionary.select(
            'Choose your Phase instance type:',
            choices=['☁️ Phase Cloud', '🛠️ Self Hosted']
        ).ask()
        
        # Fetch local username and hostname. To be used as title for personal access token
        username = os.getlogin()
        hostname = platform.node()
        personal_access_token_name = f"{username}@{hostname}"

        # Set up the PHASE_API_HOST variable
        if phase_instance_type == '🛠️ Self Hosted':
            PHASE_API_HOST = questionary.text("Please enter your host (URL eg. https://example.com/path):").ask()
            webbrowser.open(f"{PHASE_API_HOST}/webauth#{port}-{public_key.hex()}-{personal_access_token_name}")
        else:
            PHASE_API_HOST = PHASE_CLOUD_API_HOST
            webbrowser.open(f"{PHASE_API_HOST}/webauth#{port}-{public_key.hex()}-{personal_access_token_name}")

        # 3. Wait for the POST request from the web UI.
        while not server.received_data:
            time.sleep(1)

        # 4. Extract credentials from the received data
        user_email = server.received_data.get('email')
        pss = server.received_data.get('pss')

        if not (user_email and pss):
            raise ValueError("Email or pss not received from the web UI.")

        # 5. Authenticate with the received credentials.
        phase = Phase(init=False, pss=pss, host=PHASE_API_HOST)
        result = phase.auth()

        if result == "Success":
            user_data = phase.init()
            user_id = user_data["user_id"]
            offline_enabled = user_data["offline_enabled"]
            wrapped_key_share = None if not offline_enabled else user_data["wrapped_key_share"]

            # Save the credentials in the Phase keyring
            keyring.set_password(f"phase-cli-user-{user_id}", "pss", pss)

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
            
            print("✅ Authentication successful. Credentials saved in the Phase keyring.")
        else:
            print("Failed to authenticate with the provided credentials.")
    except KeyboardInterrupt:
        sys.exit(0)
    except Exception as e:
        print(f"An error occurred: {e}")
        sys.exit(1)
    finally:
        server.shutdown()
