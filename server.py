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

HOST = "0.0.0.0"
PORT = 12345

# ---------- Shared state ----------------------------------------------------
clients = {}        # username -> socket
rooms = {}          # room_id -> {"name": str, "members": set[str]}
next_room_id = 1
lock = threading.Lock() # Global lock for all shared data access

# ---------- Helper functions ------------------------------------------------
def send_json(sock: socket.socket, data: dict, target_username: str = "Unknown"):
    """Send dict as JSON + newline, handling potential socket errors."""
    try:
        message = json.dumps(data) + "\n"
        sock.sendall(message.encode())
        print(f"[DEBUG-SERVER] Sent to {target_username}: {data}")
    except (BrokenPipeError, ConnectionResetError, OSError) as e:
        # These errors mean the client disconnected.
        # The handle_client function's finally block will deal with cleanup.
        print(f"[ERROR-SERVER] Error sending to socket for {target_username}: {e}. Client likely disconnected.")
        # Do not re-raise, allow the client handling thread to clean up.
    except Exception as e:
        print(f"[ERROR-SERVER] Unexpected error sending JSON to {target_username}: {e}")

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
                rinfo["members"].remove(username)
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


# ---------- Client handler --------------------------------------------------
def handle_client(sock: socket.socket, addr):
    global next_room_id
    buffer = ""
    username = "" # Initialize username to empty string

    try:
        # --- handshake: first line is the username --------------------------
        sock.settimeout(10) # 10 seconds to send username
        username_data = sock.recv(1024).decode().strip()
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
        print(f"[SERVER] {username} connected from {addr}")
        broadcast_global(f"[{username}] joined the chat.", exclude_sock=sock)

        # --- main loop ------------------------------------------------------
        while True:
            data = sock.recv(4096)
            if not data: # Client disconnected gracefully
                print(f"[SERVER] Client {username} disconnected gracefully.")
                break
            buffer += data.decode()

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
                    else:
                        send_json(
                            sock,
                            {
                                "type": "system",
                                "message": f"User '{recipient}' not found.",
                            },
                            target_username=username
                        )

                # ---------- room create ----------------
                elif mtype == "room_create":
                    print(f"[SERVER] Processing room create from {username}")
                    room_name = msg.get("room_name") or "Untitled"
                    new_room_id = ""
                    with lock:
                        new_room_id = str(next_room_id)
                        next_room_id += 1
                        rooms[new_room_id] = {"name": room_name, "members": set()}
                        # Auto-join creator
                        rooms[new_room_id]["members"].add(username)
                    send_json(
                        sock,
                        {
                            "type": "room_joined",
                            "room_id": new_room_id,
                            "room_name": room_name,
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
                        rinfo = rooms.get(rid)
                    
                    if rinfo:
                        with lock:
                            # Check if already in room
                            if username in rinfo["members"]:
                                send_json(sock, {"type": "system", "message": f"You are already in room {rid}."}, target_username=username)
                                continue
                            rinfo["members"].add(username)
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

                # ---------- exit -----------------------
                elif mtype == "exit":
                    print(f"[SERVER] {username} sent exit command. Initiating cleanup.")
                    break # Break out of the main loop to trigger cleanup

    except (ConnectionResetError, BrokenPipeError, OSError) as e:
        print(f"[ERROR-SERVER] Connection error for {username} ({addr}): {e}")
    except Exception as e:
        print(f"[ERROR-SERVER] Unhandled error in handle_client for {username} ({addr}): {e}")
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
        sock.close()
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
    main()
