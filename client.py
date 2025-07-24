# client.py
import json
import socket
import threading
import sys
import commands
import base64

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import os

# Global flag to signal threads to stop
STOP_THREADS = False
client_priv_key = None


def generate_keys():
    """Generate RSA key pair"""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    return private_key, public_key

def save_keys(private_key, public_key, filename_prefix):
    """Save keys to files"""
    # Save private key
    with open(f"{filename_prefix}_private.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    # Save public key
    with open(f"{filename_prefix}_public.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

def load_private_key(filename):
    """Load private key from file"""
    with open(filename, "rb") as key_file:
        return serialization.load_pem_private_key(
            key_file.read(),
            password=None
        )

def load_public_key(filename):
    """Load public key from file"""
    with open(filename, "rb") as key_file:
        return serialization.load_pem_public_key(
            key_file.read()
        )

def encrypt_message(message, public_key):
    """Encrypt a message with RSA public key"""
    encrypted = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(encrypted).decode()

def decrypt_message(encrypted_message, private_key):
    """Decrypt a message with RSA private key"""
    try:
        decrypted = private_key.decrypt(
            base64.b64decode(encrypted_message.encode()),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted.decode()
    except Exception as e:
        print(f"[ERROR] Decryption failed: {e}")
        return None
    
    
# ---------- Receive thread --------------------------------------------------
def _receiver(sock: socket.socket, state: dict , client_priv_key):
    print("[DEBUG-CLIENT] Sender/Receiver loop running") #yes

    """
    Listens for JSON messages from the server and prints them.
    Updates state['current_room'] when server confirms room actions.
    """
    global STOP_THREADS
    buffer = ""
    while not STOP_THREADS:
        try:
            sock.settimeout(0.5) # 500ms timeout to periodically check STOP_THREADS
            data = sock.recv(4096).decode()
            sock.settimeout(None) # Reset timeout

            if not data:  # server closed or no data received within timeout
                print("\n[Client] Server connection closed.")
                STOP_THREADS = True
                break

            buffer += data
            while "\n" in buffer:  # newline‑delimited protocol
                line, buffer = buffer.split("\n", 1)
                if not line:
                    continue

                try:
                    decrypted = decrypt_message(line, client_priv_key)
                    if decrypted:
                        msg = json.loads(decrypted)
                    else:
                        msg = json.loads(line)
                    print(f"[DEBUG-CLIENT] Received from server: {msg}")
                except json.JSONDecodeError:
                    print(f"[ERROR-CLIENT] Malformed message from server: {line}")
                    continue

                mtype = msg.get("type")

                # --- System messages we care about ---
                print(f"[DEBUG-CLIENT] Received message type: {mtype}") #yes
                if mtype == "system":
                    print(f"[System] {msg.get('message')}")
                elif mtype == "room_created":
                    state["current_room"] = msg.get("room_id")
                    print(f"[DEBUG-CLIENT] Client state updated: current_room = {state['current_room']}")
                    print(
                        f"[System] Joined room {state['current_room']} "
                        f"({msg.get('room_name')}) "
                        "You are the admin now"
                    )
                elif mtype == "room_joined":
                    state["current_room"] = msg.get("room_id")
                    print(f"[DEBUG-CLIENT] Client state updated: current_room = {state['current_room']}")
                    print(
                        f"[System] Joined room {state['current_room']} "
                        f"({msg.get('room_name')})"
                    )
                elif mtype == "room_left":
                    state["current_room"] = None
                    print(f"[DEBUG-CLIENT] Client state updated: current_room = {state['current_room']}")
                    print("[System] Left the current room.")
                elif mtype == "switch":
                    target_rid = msg.get("target_rid")
                    state["current_room"] = target_rid
                    print(f"[DEBUT-CLIENT] Client state updated: current_room = {state['current_room']}") 
                    print(
                        f"[System] Switched to room {state['current_room']} "
                        f"({msg.get('target_rname')})"
                    )
                elif mtype == "join_request":
                    print(msg.get("message"))
                elif mtype == "room": # Room specific messages (like broadcasts within a room)
                    print(msg.get("display", f"[{msg.get('room_id', 'Unknown Room')}]: {msg.get('message', 'No message')}"))
                elif mtype == "get_achievement":
                    print(f"\n🎉 {msg.get('message')} ({msg.get('name')})\n")
                else:
                    # Fallback: server already rendered 'display' or
                    # simply show raw message
                    print(msg.get("display", line))

        except socket.timeout:
            continue # Timeout occurred, loop back to check STOP_THREADS
        except (ConnectionResetError, BrokenPipeError, OSError) as e:
            print(f"\n[ERROR-CLIENT] Connection lost: {e}")
            STOP_THREADS = True
            break
        except Exception as e:
            print(f"\n[ERROR-CLIENT] An unexpected error occurred in receiver: {e}")
            STOP_THREADS = True
            break


# ---------- Send thread -----------------------------------------------------
def _sender(sock: socket.socket, username: str, state: dict):
    print("[DEBUG-CLIENT] Sender/Receiver loop running") #yes
    """
    Reads user input, parses commands via commands.parse,
    and sends JSON to server.
    """
    global STOP_THREADS
    while not STOP_THREADS:
        try:
            user_input = input("> ")
        except EOFError:
            user_input = "/exit"
        except KeyboardInterrupt:
            user_input = "/exit"
            print("\n")

        print(f"[DEBUG-CLIENT] User input: '{user_input}'")
        print(f"[DEBUG-CLIENT] Current room state for parsing: {state['current_room']}")
        cmd = commands.parse(user_input, username, state["current_room"])
        print(f"[DEBUG-CLIENT] Parsed command: {cmd.payload} (Error: {cmd.error})")

        if cmd.error:
            print(f"[Error] {cmd.error}")
            continue

        if cmd.message:
            print(f"[MESSAGE] {cmd.message}")
            continue

        if cmd.payload["type"] == "exit":
            try:
                sock.sendall((json.dumps(cmd.payload) + "\n").encode())
            except (BrokenPipeError, ConnectionResetError, OSError):
                pass
            STOP_THREADS = True
            break

        if cmd.payload["type"] == "room_leave":
            state["current_room"] = None  # Immediately clear the room ID
            print(f"[DEBUG-CLIENT] Force-cleared current_room due to /room leave")

        try:
            sock.sendall((json.dumps(cmd.payload) + "\n").encode())
            print(f"[DEBUG-CLIENT] Sent payload to server: {cmd.payload}")
        except (BrokenPipeError, ConnectionResetError, OSError) as e:
            print(f"[ERROR-CLIENT] Failed to send message: {e}. Server connection lost.")
            STOP_THREADS = True
            break
        except Exception as e:
            print(f"[ERROR-CLIENT] Unexpected error sending message: {e}")
            STOP_THREADS = True
            break


# ---------- Main ------------------------------------------------------------
def main():
    global STOP_THREADS
    host = input("Server IP (default 127.0.0.1): ") or "127.0.0.1"
    port = int(input("Port (default 12345): ") or "12345")
    username = input("Username: ").strip()
    client_priv_key = load_private_key("client_private.pem")
    if not username:
        print("Username cannot be empty. Exiting.")
        sys.exit(1)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((host, port))
    except ConnectionRefusedError:
        print(f"Connection refused. Is the server running on {host}:{port}?")
        sys.exit(1)
    except OSError as e:
        print(f"Network error: {e}")
        sys.exit(1)

        if not os.path.exists("client_private.pem"):
        priv_key, pub_key = generate_keys()
        save_keys(priv_key, pub_key, "client")
    
    # Load client keys
    client_priv_key = load_private_key("client_private.pem")
    client_pub_key = load_public_key("client_public.pem")
    
    # Receive server's public key
    data = sock.recv(4096).decode()
    server_pub_key = serialization.load_pem_public_key(
        json.loads(data)["public_key"].encode()
    )
    
    # Send client's public key to server
    sock.sendall(json.dumps({
        "type": "key_exchange",
        "public_key": client_pub_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
    }).encode())
    
    try:
        sock.sendall((username + "\n").encode())
    except (BrokenPipeError, ConnectionResetError, OSError) as e:
        print(f"Failed to send username: {e}. Server connection lost immediately.")
        sock.close()
        sys.exit(1)

    state = {"current_room": None}

    receiver_thread = threading.Thread(target=_receiver, args=(sock, state,client_priv_key), daemon=True,)
    receiver_thread.start()

    _sender(sock, username, state)

    if receiver_thread.is_alive():
        receiver_thread.join(timeout=1)

    sock.close()
    print("[Client] Disconnected from server. Exiting.")
    sys.exit(0)


if __name__ == "__main__":
    if not os.path.exists("server_private.pem"):
        priv_key, pub_key = generate_keys()
        save_keys(priv_key, pub_key, "server")
    main()
