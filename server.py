#!/usr/bin/env python3
"""
Multi‑room chat server for terminal client.

Message protocol (newline‑delimited JSON):
  └─ From client ....................................
        {"type": "broadcast", "sender": "...", "message": "..."}
        {"type": "private",   "sender": "...", "recipient": "...", "message": "..."}
        {"type": "room_create", "sender": "...", "room_name": "..."}
        {"type": "room_join",   {"sender": "...", "room_id": "..."}
        {"type": "room_leave",  "sender": "..."}
        {"type": "room_message","sender": "...", "room_id": "...", "message": "..."}
        {"type": "room_list",   "sender": "..."}
        {"type": "exit"}   # client intends to quit
  └─ From server ....................................
        {"type": "system", "message": "..."}                 # global notice
        {"type": "room_joined","room_id": "...","room_name":"..."}  # confirmation
        {"type": "room_left"}                                 # confirmation
        {"type": "room", "room_id": "...", "display": "..."}  # room broadcast
        ... or any text fallback (legacy clients)
"""

import json
import socket
import threading
import time

import base64

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import os

HOST = "0.0.0.0"
PORT = 12345

# ---------- Shared state ----------------------------------------------------
clients = {}        # username -> socket
rooms = {}          # room_id -> {"name": str, "members": set[str]}
next_room_id = 1
lock = threading.Lock() # Global lock for all shared data access
client_keys = {}  # username -> public_key
public_key = None
# ---------- Achievements state ----------------------------------------------
ACHIEVEMENT_LIST = {
    "first_words": "First Words",
    "chatterbox": "Chatterbox",
    "keyboard_warrior": "Keyboard Warrior",
    "private_talker": "Private Talker",
    "social_butterfly": "Social Butterfly",
    "roomie": "Roomie",
    "loner_no_more": "Loner No More",
    "room_creator": "Room Creator",
    "explorer": "Explorer"
}
achievements = {}   # username -> {achievement_code: bool}
user_stats = {}     # username -> stats dict

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

def unlock_achievement(username, code, sock=None):
    with lock:
        if username not in achievements:
            achievements[username] = {}
        if achievements[username].get(code):
            return
        achievements[username][code] = True
    if sock is None:
        with lock:
            sock = clients.get(username)
    if sock:
        send_json(sock, {
            "type": "achievement",
            "code": code,
            "name": ACHIEVEMENT_LIST[code],
            "message": f"Achievement Unlocked: {ACHIEVEMENT_LIST[code]}"
        }, target_username=username)
        print(f"[ACHIEVEMENT] {username} unlocked {ACHIEVEMENT_LIST[code]}")

def update_user_stats(username, key, value=1):
    with lock:
        if username not in user_stats:
            user_stats[username] = {
                "messages_sent": 0,
                "private_sent": 0,
                "private_targets": set(),
                "rooms_joined": set(),
                "rooms_created": 0
            }
        if key == "private_targets":
            user_stats[username][key].add(value)
        elif key == "rooms_joined":
            user_stats[username][key].add(value)
        elif key == "rooms_created":
            user_stats[username][key] += value
        else:
            user_stats[username][key] += value

    print(f"[DEBUG-STATS] Updated stats for {username}: {user_stats[username]}")
# ---------- Helper functions ------------------------------------------------
def send_json(sock: socket.socket, data: dict, target_username: str = "Unknown"):
    """Send dict as JSON + newline, handling potential socket errors."""
    try:
        message = json.dumps(data)
        if public_key:  # If we have recipient's public key
            encrypted = encrypt_message(message, public_key)
            sock.sendall((encrypted + "\n").encode())
        else:
            sock.sendall((message + "\n").encode())
    except Exception as e:
        print(f"[ERROR] Error sending message: {e}")

def broadcast_global(msg: str, exclude_sock=None):
    """Send plain system text to every client."""
    sockets_to_send = []
    with lock:
        sockets_to_send = list(clients.items()) # Get items to access username

    for user, csock in sockets_to_send:
        if csock is exclude_sock:
            continue
        send_json(csock, {"type": "system", "message": msg}, target_username=user)

def broadcast_room(room_id: str, data: dict, exclude_user=None):
    """Broadcast JSON data inside one room."""
    members_in_room = set()
    with lock:
        if room_id in rooms:
            members_in_room = rooms[room_id]["members"].copy()
        else:
            print(f"[DEBUG-SERVER] Attempted to broadcast to non-existent room {room_id}")
            return

    for member in members_in_room:
        if member == exclude_user:
            continue
        with lock: # Acquire lock to safely get client socket
            csock = clients.get(member)
        if csock:
            send_json(csock, data, target_username=member)

def remove_user_from_all_rooms(username: str):
    """Remove user from every room and alert remaining members.
    Also deletes rooms that become empty."""
    print(f"[DEBUG-SERVER] Initiating remove_user_from_all_rooms for {username}")
    with lock:
        empty_rooms = []
        for rid, rinfo in list(rooms.items()): # Iterate over a copy of items
            if username in rinfo["members"]:
                rinfo["members"].discard(username)
                rinfo["admins"].discard(username)
                print(f"[DEBUG-SERVER] Removed {username} from room {rid}.")
                # Notify others in that room
                broadcast_room(
                    rid,
                    {
                        "type": "room",
                        "room_id": rid,
                        "display": f"[{username}] left room.",
                    },
                    exclude_user=username,
                )
                if not rinfo["members"]:
                    empty_rooms.append(rid)
        # Delete empty rooms outside the main iteration
        for rid in empty_rooms:
            print(f"[SERVER] Deleting empty room: {rid} ({rooms[rid]['name']})")
            del rooms[rid]
    print(f"[DEBUG-SERVER] Finished remove_user_from_all_rooms for {username}")


# ----------------- remove a user from the room -----------------------------
# def remove_from_room(username : str, room_id: str):
#     print(f"[DEBUG-SERVER] Initiating remove_from_room for {username}")
#     with lock:
#         if username in rooms[room_id]["members"]:
#             rooms[room_id]["members"].discard(username)
#             print(f"[DEBUG-SERVER] removed {username} from {room_id}")
#             broadcast_room(
#                     room_id,
#                     {
#                         "type": "room",
#                         "room_id": room_id,
#                         "display": f"[{username}] left room.",
#                     },
#                     exclude_user=username,
#                 )

# ---------- Client handler --------------------------------------------------
def handle_client(sock: socket.socket, addr):
    global next_room_id
    buffer = ""
    username = "" # Initialize username to empty string

    try:
        # --- handshake: first line is the username --------------------------
        sock.settimeout(30) # 30 seconds to send username (increased from 10)
        try:
            username_data = sock.recv(1024).decode().strip()
        except socket.timeout:
            print(f"[SERVER] Client from {addr} timed out during username handshake.")
            sock.close()
            return
        except (ConnectionResetError, BrokenPipeError, OSError) as e:
            print(f"[SERVER] Client from {addr} disconnected during handshake: {e}")
            sock.close()
            return
        finally:
            sock.settimeout(None) # Remove timeout after handshake

        
        if not username_data:
            print(f"[SERVER] Client from {addr} disconnected before sending username.")
            sock.close()
            return

        username = username_data
        with lock:
            if username in clients:
                send_json(sock, {"type": "system", "message": "Username taken. Please choose another."}, target_username=username)
                print(f"[SERVER] Connection from {addr} rejected: Username '{username}' taken.")
                sock.close()
                return
            clients[username] = sock
            # Initialize achievements and stats
            if username not in achievements:
                achievements[username] = {}
            if username not in user_stats:
                user_stats[username] = {
                    "messages_sent": 0,
                    "private_sent": 0,
                    "private_targets": set(),
                    "rooms_joined": set(),
                    "rooms_created": 0
                }
            print(f"[SERVER] {username} connected from {addr}")
            send_json(sock, {
                "type": "system",
                "message": f"Welcome {username}! Type /help to view all the commands."
            }, target_username= username)
        
            server_pub_key = load_public_key("server_public.pem")
            send_json(sock, {
                "type": "key_exchange",
                "public_key": server_pub_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ).decode()
            })

            try:
                msg = json.loads(sock.recv(4096).decode())
                if msg.get("type") == "key_exchange":
                    client_pub_key = serialization.load_pem_public_key(
                        msg["public_key"].encode()
                    )
                    with lock:
                        client_keys[username] = client_pub_key
            except Exception as e:
                print(f"[ERROR] Key exchange failed: {e}")
                sock.close()
                return
        
        broadcast_global(f"[{username}] joined the chat.", exclude_sock=sock)
        print(f"[SERVER] {username} has joined the server.")

        # --- main loop ------------------------------------------------------
        while True:
            try:
                # Use a short timeout to periodically check if we should continue
                sock.settimeout(1.0)
                data = sock.recv(4096)
                sock.settimeout(None)
                
                if not data: # Client disconnected gracefully
                    print(f"[SERVER] Client {username} disconnected gracefully.")
                    break
                    
                buffer += data.decode()
            except socket.timeout:
                # This is normal - just continue the loop
                continue
            except (ConnectionResetError, BrokenPipeError, OSError) as e:
                print(f"[SERVER] Client {username} connection lost: {e}")
                break

            while "\n" in buffer:
                line, buffer = buffer.split("\n", 1)
                if not line: # Handle empty lines
                    continue
                try:
                    msg = json.loads(line)
                    print(f"[DEBUG-SERVER] Received from {username}: {msg}")
                except json.JSONDecodeError:
                    print(f"[ERROR-SERVER] Received malformed JSON from {username}: {line}")
                    continue # Skip this malformed line and continue processing buffer

                mtype = msg.get("type")

                # ---------- public broadcast -----------
                if mtype == "broadcast":
                    print(f"[SERVER] Processing broadcast from {username}")
                    text = f"[{msg.get('sender', 'Unknown')}]: {msg.get('message', '')}"
                    broadcast_global(text)
                    # Achievements: First Words, Chatterbox, Keyboard Warrior
                    update_user_stats(username, "messages_sent")
                    count = user_stats[username]["messages_sent"]
                    if count == 1:
                        unlock_achievement(username, "first_words", sock)
                    if count == 10:
                        unlock_achievement(username, "chatterbox", sock)
                    if count == 50:
                        unlock_achievement(username, "keyboard_warrior", sock)

                # ---------- private --------------------
                elif mtype == "private":
                    print(f"[SERVER] Processing private message from {username}")
                    recipient = msg.get("recipient")
                    message_text = msg.get("message", "")
                    if not recipient or not message_text:
                        send_json(sock, {"type": "system", "message": "Invalid private message format."}, target_username=username)
                        continue

                    with lock:
                        rsock = clients.get(recipient)
                    if rsock:
                        send_json(
                            rsock,
                            {
                                "type": "system",
                                "message": f"[Private from {username}]: {message_text}",
                            },
                            target_username=recipient
                        )
                        # Achievements: Private Talker, Social Butterfly
                        update_user_stats(username, "private_sent")
                        update_user_stats(username, "private_targets", recipient)
                        if user_stats[username]["private_sent"] == 1:
                            unlock_achievement(username, "private_talker", sock)
                        if len(user_stats[username]["private_targets"]) == 5:
                            unlock_achievement(username, "social_butterfly", sock)
                    else:
                        send_json(
                            sock,
                            {
                                "type": "system",
                                "message": f"User '{recipient}' not found.",
                            },
                            target_username=username
                        )
                         
                # ---------- Change username --------------
                elif mtype == "rename":
                    new_name = msg.get("new_name")

                    if not new_name:
                        send_json(sock, {"type": "system", "message": "No new username provided"}, target_username=username)
                        continue

                    with lock:
                        if new_name in clients:
                            send_json(sock, {"type": "system", "message": "Username not available"}, target_username=username)
                            continue

                        print(f"[DEBUG_RENAME] Proccesing rename for {username}")
                        clients[new_name] = clients.pop(username)


                        for rid, rinfo in rooms.items():
                            if username in rinfo["members"]:
                                rinfo["members"].discard(username)
                                rinfo["members"].add(new_name)
                            if username in rinfo["admins"]:
                                rinfo["admins"].discard(username)
                                rinfo["admins"].add(new_name)
                            if username == rinfo["super_admin"]:
                                rinfo["super_admin"] = new_name
                            if username in rinfo["banned"]:
                                rinfo["banned"].discard(username)
                                rinfo["banned"].add(new_name)

                    broadcast_global(f"{username} changed their username to {new_name}", exclude_sock = username)
                    send_json(sock, {"type": "system", "message": f"Your username has been changed to {new_name}"}, target_username=new_name)

                    print(f"[DEBUG_RENAME] Username of {username} changed to {new_name}")

                    # Updating new_name to client thread
                    username = new_name

                # ---------- room create ----------------
                elif mtype == "room_create":
                    print(f"[SERVER] Processing room create from {username}")
                    room_name = msg.get("room_name") or "Untitled"
                    new_room_id = ""
                    with lock:
                        new_room_id = str(next_room_id)
                        next_room_id += 1
                        rooms[new_room_id] = {
                            "name": room_name, 
                            "members": set(), 
                            "admins": set(), 
                            "super_admin": str, 
                            "banned": set()}
                        # Auto-join creator
                        rooms[new_room_id]["members"].add(username)
                        rooms[new_room_id]["admins"].add(username)
                        rooms[new_room_id]["super_admin"] = username
                        # Achievements: Room Creator
                        update_user_stats(username, "rooms_created")
                        if user_stats[username]["rooms_created"] == 1:
                            unlock_achievement(username, "room_creator", sock)

                    send_json(
                        sock,
                        {
                            "type": "room_joined",
                            "room_id": new_room_id,
                            "room_name": room_name,
                            "message": f"Room '{room_name}' created. You are the admin now"
                        },
                        target_username=username
                    )
                    print(f"[SERVER] {username} created room {new_room_id} ({room_name})")

                # ---------- room join ------------------
                elif mtype == "room_join":
                    print(f"[SERVER] Processing room join from {username}")
                    rid = msg.get("room_id")
                    if not rid:
                        send_json(sock, {"type": "system", "message": "Please specify a room ID to join."}, target_username=username)
                        continue
                    
                    rinfo = None
                    with lock:
                        rid = str(rid)
                        rinfo = rooms.get(rid)
                        owner = rooms[rid]["super_admin"]
                    
                    if rinfo:
                        with lock:
                            # Check if already in room
                            if username in rinfo["members"]:
                                send_json(sock, {"type": "system", "message": f"You are already in room {rid}."}, target_username=username)
                                continue
                            # Check if banned in the room
                            elif username in rinfo["banned"]:
                                send_json(sock, {"type": "system", "message": f"You are banned in room {rid}."}, target_username=username)
                                continue

                            already_members = len(rinfo["members"]) > 0
                            rinfo["members"].add(username)
                            update_user_stats(username, "rooms_joined", rid)
                            # Roomie
                            if len(user_stats[username]["rooms_joined"]) == 1:
                                unlock_achievement(username, "roomie", sock)
                            # Explorer
                            if len(user_stats[username]["rooms_joined"]) == 3:
                                unlock_achievement(username, "explorer", sock)
                            # Loner No More
                            if already_members:
                                unlock_achievement(username, "loner_no_more", sock)
                            print(f"[DEBUG-JOIN] Current members in room {rid}: {rinfo['members']}")
                        send_json(
                            sock,
                            {
                                "type": "room_joined",
                                "room_id": rid,
                                "room_name": rinfo["name"],
                            },
                            target_username=username
                        )
                        broadcast_room(
                            rid,
                            {
                                "type": "room",
                                "room_id": rid,
                                "display": f"[{username}] joined room.",
                            },
                            exclude_user=username,
                        )
                        print(f"[SERVER] {username} joined room {rid} ({rinfo['name']})")
                    else:
                        send_json(
                            sock,
                            {"type": "system", "message": "Room not found."},
                            target_username=username
                        )

                # ---------- room leave -----------------
                elif mtype == "room_leave":
                    print(f"[SERVER] Processing room leave from {username}")
                    remove_user_from_all_rooms(username)
                    send_json(sock, {"type": "room_left"}, target_username=username)
                    # After leaving, the client should still be able to send commands.
                    # The server thread for this client remains active.
                    print(f"[SERVER] {username} left all rooms. Client connection remains active.")

                # ---------- room list ------------------
                elif mtype == "room_list":
                    print(f"[SERVER] Processing room list from {username}")
                    listing = []
                    with lock:
                        for rid, r in rooms.items():
                            listing.append(
                                {"id": rid, "name": r["name"], "size": len(r["members"])}
                            )
                    send_json(
                        sock,
                        {"type": "system", "message": f"Available Rooms: {listing}"},
                        target_username=username
                    )

                # ---------- leave from a room ----------
                # elif mtype == "leave_room":
                #     print(f"[SERVER] Processing leave room from {username}")
                #     target = msg.get("target")
                #     room_id = str(msg.get("room_id"))
                #     remove_from_room(username, room_id)
                #     send_json(sock, {"type": "left"}, target_username = target)

                # ---------- room_message ---------------
                elif mtype == "room_message":
                    print(f"[SERVER] Processing room message from {username}")
                    rid = msg.get("room_id")
                    text = msg.get("message", "")
                    if not rid or not text:
                        send_json(sock, {"type": "system", "message": "Invalid room message format."}, target_username=username)
                        continue

                    with lock:
                        is_member = rid in rooms and username in rooms[rid]["members"]

                    if is_member:
                        display = f"[{rid}] {username}: {text}"
                        broadcast_room(
                            rid,
                            {"type": "room", "room_id": rid, "display": display},
                        )
                    else:
                        send_json(sock, {"type": "system", "message": "You are not in this room or room does not exist."}, target_username=username)

                # ---------- promoting/demoting a user as admin(only admins can make it) ---
                elif mtype == "room_promote":
                    sender = msg.get("sender")
                    target = msg.get("target")
                    room_id = str(msg.get("room_id"))

                    if not sender or not target or not room_id:
                        send_json(sock, {"type": "system", "message": "[ERROR] Invalid admin command."}, target_username=username)
                        continue

                    with lock:
                        room = rooms.get(room_id)
                        if not room:
                            send_json(sock, {"type": "system", "message": f"Room {room_id} does not exist."}, target_username=username)
                            continue

                        if sender not in room["admins"]:
                            send_json(sock, {"type": "system", "message": "Only admins can modify admin privileges."}, target_username=username)
                            continue

                        if target not in room["members"]:
                            send_json(sock, {"type": "system", "message": f"{target} is not a member of the room."}, target_username=username)
                            continue

                        if target in room["admins"]:
                            send_json(sock, {"type": "system", "message": f"{target} is already an admin."}, target_username=username)
                            continue

                        # Apply promote 
                        room["admins"].add(target)
                        system_msg = f"{target} has been promoted to admin by {sender}."
                        personal_msg = f"You are promoted to admin for the room {room_id} by {sender}."
                        
                        if target in clients:
                            send_json(clients[target], {
                                "type": "system",
                                "message": personal_msg
                            }, target_username=target)

                        broadcast_room(room_id, {
                            "type": "system",
                            "message": system_msg
                        })

                        print(f"[ADMIN] {sender} promoted {target} to admin in room {room_id}")

                elif mtype == "room_demote":
                    sender = msg.get("sender")
                    target = msg.get("target")
                    room_id = str(msg.get("room_id"))

                    if not sender or not target or not room_id:
                        send_json(sock, {"type": "system", "message": "[ERROR] Invalid admin command."}, target_username=username)
                        continue

                    with lock:
                        room = rooms.get(room_id)
                        if not room:
                            send_json(sock, {"type": "system", "message": f"Room {room_id} does not exist."}, target_username=username)
                            continue

                        if sender not in room["admins"]:
                            send_json(sock, {"type": "system", "message": "Only admins can modify admin privileges."}, target_username=username)
                            continue

                        if target not in room["members"]:
                            send_json(sock, {"type": "system", "message": f"{target} is not a member of the room."}, target_username=username)
                            continue

                        # Protect super admin
                        if target == room["super_admin"]:
                            send_json(sock, {"type": "system", "message": f"{target} cannot be removed as admin. {target} is the owner of the room."}, target_username=username)
                            continue
                        
                        if target not in room["admins"]:
                            send_json(sock, {"type": "system", "message": f"{target} is not an admin."}, target_username=username)
                            continue
                        
                        # Apply demote (FIXED: was incorrectly promoting)
                        room["admins"].discard(target)
                        system_msg = f"{target} has been demoted from admin by {sender}."
                        personal_msg = f"You have been demoted from admin for room {room_id} by {sender}."
                        
                        if target in clients:
                            send_json(clients[target], {
                                "type": "system",
                                "message": personal_msg
                            }, target_username=target)

                        broadcast_room(room_id, {
                            "type": "system",
                            "message": system_msg
                        })

                        print(f"[ADMIN] {sender} demoted {target} from admin in room {room_id}")

                # ---------- kick a target from the room ---------
                elif mtype == "room_kick":
                    sender = msg.get("sender")
                    target = msg.get("target")
                    room_id = str(msg.get("room_id"))

                    if not sender or not target or not room_id:
                        send_json(sock, {"type": "system", "message": "[ERROR] Invalid kick command"}, target_username=username)
                        continue
                    
                    with lock:
                        room = rooms.get(room_id)
                        if not room:
                            send_json(sock, {"type": "system", "message": f"Room {room_id} does not exist"}, target_username=username)
                            continue
                        
                        if sender not in room["admins"]:
                            send_json(sock, {"type":"system", "message": "Only admins can kick users from this room."}, target_username=username)
                            continue
                        
                        if target not in room["members"]:
                            send_json(sock, {"type": "system", "message": f"{target} is not in the room {room_id}"}, target_username=username)
                            continue
                        
                        if target == room["super_admin"]:
                            send_json(sock, {"type": "system", "message": "Cannot kick the owner of the room"}, target_username=username)
                            continue

                        # Remove the target from the saved lists
                        print(f"[DEBUG] Before kicking: members = {room['members']}, admins = {room['admins']}")

                        room["members"].discard(target)
                        room["admins"].discard(target)

                        print(f"[DEBUG] After kicking: members = {room['members']}, admins = {room['admins']}")

                        # Notify the kicked user
                        if target in clients: 
                            try:
                                send_json(clients[target], {
                                    "type": "system",
                                    "message": f"You were kicked from the room {room_id} by {sender}."
                                }, target_username=target)
                                send_json(clients[target], {
                                    "type": "room_left"
                                }, target_username=target)
                            except:
                                pass

                        print(f"[DEBUG-KICK] Room members for {room_id}: {room['members']}")

                        # Notify others in the room
                        broadcast_room(room_id, {
                            "type":"system", 
                            "message": f"{target} was kicked from the room by {sender}."
                        })


                    print(f"[KICK] {sender} kicked {target} from room {room_id}")

                # ----------------- ban from room -----------------------------    
                elif mtype == "room_ban":
                    room_id = str(msg.get("room_id"))
                    sender = msg.get("sender")
                    target = msg.get("target")
                    
                    with lock:
                        room = rooms.get(room_id)

                        if not sender or not target or not room_id:
                            send_json(sock, {"type": "system", "message": "[ERROR] Invalid Command!"}, target_username = username)
                            continue

                        if room_id not in rooms:
                            send_json(sock, {"type": "system", "message": f"Room {room_id} doesn't exist"}, target_username = username)
                            continue

                        if sender not in room["admins"]:
                            send_json(sock, {"type": "system", "message": "Only admins are allowed to ban someone"}, target_username= username)
                            continue

                        if target not in room["members"]:
                            send_json(sock, {"type":"system", "message": f"[ERROR] {target} is not in room {room_id}"}, target_username= username)
                            continue

                        if target == room["super_admin"]:
                            send_json(sock, {"type": "system", "message": "Cannot ban owner of the room"}, target_username= username)
                            continue

                        # Remove the target from the saved lists
                        print(f"[DEBUG] Before banning: members = {room['members']}, admins = {room['admins']}")

                        room["members"].discard(target)
                        room["admins"].discard(target)
                        room["banned"].add(target)
                        print(f"[KICK] {sender} kicked {target} from room {room_id}")
                        
                        print(f"[DEBUG] After banning: members = {room['members']}, admins = {room['admins']}")

                        if target in clients:
                            try:
                                send_json(clients[target], 
                                {
                                    "type": "system",
                                    "message": "You were banned in the room {room_id} by {sender}"
                                }, target_username = clients[target])
                                send_json(clients[target], 
                                {
                                    "type": "room_left",
                                }, target_username = clients[target])
                            except:
                                pass
                        
                        print(f"[DEBUG-BAN] Room members for room {room_id}: {room['members']}")

                    # Notify others in the room
                    broadcast_room(room_id, {
                        "type":"system", 
                        "message": f"{target} was banned in the room by {sender}."
                    })

                    print(f"[BAN] {sender} banned {target} in room {room_id}")

                # ---------- List of users in a room -----------
                elif mtype == "users_list":
                    rid = str(msg.get("room_id"))
                    sender = msg.get("sender")
                    with lock:
                        rinfo = rooms[rid]
                        members_list = list(rinfo["members"])

                    print(f"Sending users list of room {rid} to {sender}")

                    send_json(sock, {"type": "system", "message": f"Active users list of room {rid}: {members_list}"}, target_username=owner)

                    print(f"Sent the users list of room {rid} to {sender}")

                # ----------------- List of room admins ------------------------
                elif mtype == "room_admins":
                    room_id = str(msg.get("room_id"))
                    username = msg.get("sender")
                    if not room_id:
                        send_json(sock, {"type": "system", "message": "You are not in room"}, target_username = username)
                        continue

                    with lock:
                        rinfo = rooms.get(room_id)

                        if not rinfo:
                            send_json(sock, {"type": "system", "message": f"Room {room_id} does not exist."}, target_username=username)
                            continue

                        admin_list = list(rinfo["admins"])
                        send_json(sock, {"type": "system", "message" : f"Admins in room {room_id}: {admin_list}"}, target_username = username)

                # ----------- Switching room -----------------
                elif mtype == "room_switch":
                    room_id = str(msg.get("room_id"))
                    target_rid = str(msg.get("target_rid"))
                    sender = msg.get("sender")

                    #  Condition checking
                    with lock:
                        try:
                            if not sender or not room_id or not target_rid:
                                send_json(sock, {"type": "system", "message": "[ERROR] Invalid Command!"}, target_username = username)
                                continue

                            if room_id not in rooms:
                                send_json(sock, {"type": "system", "message": f"Room {room_id} doesn't exist"}, target_username = username)
                                continue

                            if target_rid not in rooms:
                                send_json(sock, {"type": "system", "message": f"Room {target_rid} doesn't exist"}, target_username = username)
                                continue

                            if sender not in rooms[target_rid]["members"]:
                                send_json(sock, {"type": "system", "message": f"You didn't joined this room yet"}, target_username=username)
                        except (Exception, SystemExit, KeyboardInterrupt) as e:
                            send_json(sock, {"type": "system", "message": f"[ERROR] Some unknown error occured"}, target_username = username)

                        print(f"[DEBUG-SWITCH] Switch request processing for {sender} ...")

                        send_json(sock, {"type": "switch", "target_rid": target_rid, "curr_rid": room_id, "target_rname" : rooms[target_rid]["name"]}, target_username = sender)

                    print(f"[DEBUG-SWITCH] {sender} switched to room {target_rid} ({rooms[target_rid]['name']})")

                # ---------- report a user in room -----------
                elif mtype == "report_user":
                    sender = msg.get("sender")
                    target = msg.get("target")
                    room_id = str(msg.get("room_id"))
                    reason = msg.get("reason")

                    with lock:
                        owner = rooms[room_id]["super_admin"]

                        # condition check
                        try:
                            if not sender or not target or not room_id:
                                send_json(sock, {"type": "system", "message": "Invalid Command!"}, target_username=sender)
                                continue
                            if target not in rooms[room_id]["members"]:
                                send_json(sock, {"type": "system", "message": f"{target} is not in this room"}, target_username=sender)
                                continue
                        except Exception as e:
                            send_json(sock, {"type": "system", "message": "Some unknown error occured."}, target_username=sender)

                        print(f"[DEBUG-REPORT] Proccesing report from {sender} in room {room_id} on {target}")

                        # sending report to owner of the room
                        send_json(clients[owner], {"type": "system", "message": f"[REPORT] {sender} sent a report on {target} for {reason}"}, target_username=owner)
                        send_json(sock, {"type": "system", "message": "Report sent successfully"}, target_username=sender)

                    print(f"[DEBUG-REPORT] Report sent to {owner}")
                    

                # ----------- Destroy the room ---------------
                # elif mtype == "room_bomb":
                #     sender = msg.get("sender")
                #     room_id = str(msg.get("room_id"))

                #     with lock:
                #         room = rooms.get(room_id)

                #     if not room:
                #         send_json(sock, {"type": "system", "message": f"You are not in a room"})

                #     if sender != rooms[room_id]["super_admin"]:
                #         send_json(sock, {"type": "system", "message": "Only owner can bomb a room"})
                #         continue

                #     broadcast_room(room_id, {
                #         "type": "system",
                #         "message": "💣This room is being bombed"
                #     })
                #     with lock:
                #         members = list(room["members"])
                #         for user in members:
                #             print(f"[DEBUG_BOMB] Removing {user} from room {room_id}")
                #             remove_user_from_all_rooms(user)

                #         del rooms[room_id]
                #         print(f"[DEBUG-BOMB] Deleted room {room_id}")

                #     send_json(sock, {"type": "system", "message": f"💣 Room {room_id} has been destroyed"}, target_username = sender)
                
                # ---------- get achievements -----------
                elif mtype == "get_achievements":
                    with lock:
                        user_ach = achievements.get(username, {})
                        unlocked = [ACHIEVEMENT_LIST[k] for k, v in user_ach.items() if v]
                    if unlocked:
                        pretty = "Your unlocked achievements:\n" + "\n".join(f"  - {a}" for a in unlocked)
                    else:
                        pretty = "You haven't unlocked any achievements yet."
                    send_json(sock, {
                        "type": "system",
                        "message": pretty
                    }, target_username=username)
                
                # ---------- exit -----------------------
                elif mtype == "exit":
                    print(f"[SERVER] {username} sent exit command. Initiating cleanup.")
                    break # Break out of the main loop to trigger cleanup

    except Exception as e:
        print(f"[ERROR-SERVER] Unhandled error in handle_client for {username} ({addr}): {e}")
        import traceback
        traceback.print_exc()
    finally:
        # -------------- cleanup -------------------
        print(f"[SERVER] Cleaning up resources for {username}...")
        with lock:
            if username in clients:
                del clients[username]
                print(f"[SERVER] Removed {username} from clients dictionary.")
        
        remove_user_from_all_rooms(username)
        
        if username: # Only broadcast global departure if username was successfully registered
            broadcast_global(f"[{username}] left the chat.")
            print(f"[SERVER] {username} disconnected.")
        
        try:
            sock.close()
        except:
            pass
        print(f"[SERVER] Socket for {username} closed.")


# ---------- Main entry ------------------------------------------------------
def main():
    print(f"Starting server on {HOST}:{PORT}")
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server_sock.bind((HOST, PORT))
        server_sock.listen()
    except OSError as e:
        print(f"[ERROR-SERVER] Error binding server socket: {e}. Is the port already in use?")
        return # Exit if binding fails

    try:
        while True:
            csock, addr = server_sock.accept()
            print(f"[SERVER] Accepted connection from {addr}")
            threading.Thread(
                target=handle_client, args=(csock, addr), daemon=True
            ).start()
    except KeyboardInterrupt:
        print("[SERVER] Server shutting down.")
    except Exception as e:
        print(f"[ERROR-SERVER] An unexpected error occurred in the server main loop: {e}")
    finally:
        server_sock.close()
        print("[SERVER] Server socket closed.")


if __name__ == "__main__":
    if not os.path.exists("server_private.pem"):
        priv_key, pub_key = generate_keys()
        save_keys(priv_key, pub_key, "server")
    main()