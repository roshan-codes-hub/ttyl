# commands.py
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
            pass

        if cmd == "all":
            return Command(user_input, _broadcast(username, " ".join(parts[1:])))

        if cmd == "msg":
            to = parts[1]
            text = " ".join(parts[2:])
            return Command(user_input, _private(username, to, text))

        if cmd == "room":
            sub = parts[1]
            if sub == "create":
                name = " ".join(parts[2:]) or "Untitled"
                return Command(
                    user_input,
                    {"type": "room_create", "sender": username, "room_name": name},
                )

            if sub == "join":
                room_id = parts[2]
                return Command(
                    user_input,
                    {"type": "room_join", "sender": username, "room_id": room_id},
                )

            if sub == "leave":
                return Command(
                    user_input, {"type": "room_leave", "sender": username}
                )

            if sub == "list":
                return Command(user_input, {"type": "room_list", "sender": username})

        if cmd == "exit":
            return Command(user_input, {"type": "exit"})
        
        if cmd == "roomid":
            pass

        if cmd == "kick":
            pass

        if cmd == "list":
            pass

    except IndexError:
        # any command missing arguments ends up here
        return Command(user_input, None, "Incomplete command")

    return Command(user_input, None, "Unrecognized command")
