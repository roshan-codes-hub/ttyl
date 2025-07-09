# commands.py - Fixed version
"""
Slash‑command handling for the terminal chat client.

Returned value: Command(raw, payload, error)
 - raw     : the original user string
 - payload : dict ready to JSON‑encode and send to server
 - error   : set if the command is invalid
"""

from dataclasses import dataclass
from typing import Dict, Any, Optional

@dataclass
class Command:
    raw: str
    payload: Optional[Dict[str, Any]]
    error: Optional[str] = None
    message: Optional[str] = None


def _broadcast(username: str, text: str) -> Dict[str, Any]:
    return {"type": "broadcast", "sender": username, "message": text}


def _private(username: str, to: str, text: str) -> Dict[str, Any]:
    return {
        "type": "private",
        "sender": username,
        "recipient": to,
        "message": text,
    }


def _room_msg(username: str, room_id: str, text: str) -> Dict[str, Any]:
    return {
        "type": "room_message",
        "sender": username,
        "room_id": room_id,
        "message": text,
    }


def parse(user_input: str, username: str, current_room: Optional[str]) -> Command:
    """Return a Command object representing user_input."""
    # ---------- Plain text (no leading slash) ----------
    if not user_input.startswith("/"):
        if current_room:
            return Command(user_input, _room_msg(username, current_room, user_input))
        return Command(user_input, _broadcast(username, user_input))

    # ---------- Slash commands ----------
    parts = user_input.strip().split()
    if not parts:  # should never happen
        return Command(user_input, None, "Empty command")

    cmd = parts[0][1:]  # remove the "/"

    try:
        if cmd == "help":
            help_text = (
                "Available Commands:\n"
                "/whoami                    - Know you username\n" 
                "/all <msg>                 - Send a global message\n"
                "/msg <user> <msg>          - Send a private message\n"
                "/room create <name>        - Create a new chat room\n"
                "/room join <id>            - Join an existing room\n"
                "/room makeadmin <user>     - Make a person in the room as admin\n"
                "/room removeasadmin <user> - Remove a person as admin in the room\n"
                "/room leave                - Leave the current room\n"
                "/room list                 - List all rooms\n"
                "/room kick <user>          - Kick the user from the room\n"
                "/roomid                    - Show current room ID\n"
                "/exit                      - Exit the chat\n"
                "/help                      - Show this help message"
            )
            return Command(user_input, {"type": "help", "sender": username}, message=help_text, error=None)
        
        if cmd == "whoami":
            return Command(user_input, {"type": "username", "sender": username}, error=None, message=f"You are {username}")

        if cmd == "all":
            return Command(user_input, _broadcast(username, " ".join(parts[1:])))

        if cmd == "msg":
            if len(parts) < 3:
                return Command(user_input, None, error="Usage: /msg <user> <message>")
            to = parts[1]
            text = " ".join(parts[2:])
            return Command(user_input, _private(username, to, text))

        if cmd == "room":
            if len(parts) < 2:
                return Command(user_input, None, error="Usage: /room <subcommand>")
            
            sub = parts[1]
            
            if sub == "create":
                name = " ".join(parts[2:]) or "Untitled"
                return Command(
                    user_input,
                    {"type": "room_create", "sender": username, "room_name": name},
                )

            elif sub == "join":
                if len(parts) < 3:
                    return Command(user_input, None, error="Usage: /room join <room_id>")
                room_id = parts[2]
                return Command(
                    user_input,
                    {"type": "room_join", "sender": username, "room_id": room_id},
                )

            elif sub == "leave":
                return Command(
                    user_input, {"type": "room_leave", "sender": username}
                )

            elif sub == "list":
                return Command(user_input, {"type": "room_list", "sender": username})
            
            elif sub == "kick":
                if len(parts) < 3:
                    return Command(user_input, None, error="Usage: /room kick <user>")
                target = parts[2]
                if not current_room:
                    return Command(user_input, None, error=None, message="You are not in any room to kick someone.")
                return Command(user_input, {
                    "type": "room_kick",
                    "sender": username,
                    "target": target,
                    "room_id": current_room
                }) 
            
            # FIX: Correct the logic error
            elif sub == "makeadmin":
                if len(parts) < 3:
                    return Command(user_input, None, error="Usage: /room makeadmin <username>")
                
                target = parts[2]
                if not current_room:
                    return Command(user_input, None, message="You are not in a room.")
                
                return Command(user_input, {
                    "type": "room_promote",
                    "sender": username,
                    "target": target,
                    "room_id": current_room
                })
            
            elif sub == "removeasadmin":
                if len(parts) < 3:
                    return Command(user_input, None, error="Usage: /room removeasadmin <username>")
                
                target = parts[2]
                if not current_room:
                    return Command(user_input, None, message="You are not in a room.")
                
                return Command(user_input, {
                    "type": "room_demote",
                    "sender": username,
                    "target": target,
                    "room_id": current_room
                })

            elif sub == "admins":
                # TODO: Implement admin listing
                return Command(user_input, None, error="Admin listing not yet implemented")
            
            else:
                return Command(user_input, None, error=f"Unknown room subcommand: {sub}")

        if cmd == "exit":
            return Command(user_input, {"type": "exit"})
        
        if cmd == "roomid":
            if current_room:
                return Command(user_input, {"type": "room_id", "sender": username}, 
                             message=f"Your current room id is {current_room}", error=None)
            else:
                return Command(user_input, {"type": "room_id", "sender": username}, 
                             error=None, message="You are not in any room currently.")

        # Unknown command
        return Command(user_input, None, error=f"Unknown command: /{cmd}")

    except IndexError:
        return Command(user_input, None, error="Incomplete command")