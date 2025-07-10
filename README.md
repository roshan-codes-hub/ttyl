"""guys i made the client.py part and a rough version of a server to handle the request for chat rooms
and other commands without any authencation or admin stuff"""


A simple terminal-based chat system using Python sockets with support for:

- Global messaging
- Private messaging
- Chat rooms

---

## 🚀 How to Run

### Start the server:
```bash
python server.py
```

### Start the client (in another terminal):
```bash
python client.py
```

You can open multiple terminals to simulate multiple users.

---

## 💬 Commands

| Command | Description |
|--------|-------------|
| `/whoami` | Gives your username |
| `/all <msg>` | Send a message to everyone |
| `/msg <user> <msg>` | Send a private message |
| `/room create <name>` | Create a new chat room |
| `/room join <id>` | Join a room by ID |
| `/room makeadmin <name>` | Makes <name> as admin |
| `/room remveasadmin <name>` | Removes <name> as admin |
| `/room leave` | Leave the current room |
| `/room list` | Show all active rooms |
| `/room kick <name>` | Kick the user from the room |
| `/room admins ` | Gives the list of admins of the room |
| `/roomid` | Show current room ID |
| `/exit` | Disconnect from the server |
| `/help ` | Shows the help box(You are looking at it right now 👀) |

---

## 📂 Files

- `server.py` – Server logic
- `client.py` – Client logic (terminal)
- `commands.py` – Client-side command parser

---

## 📌 Notes

- Messages are real-time and text-based.
- Room messages are only visible to users in that room.
- Server auto-removes users and announces when someone leaves.
