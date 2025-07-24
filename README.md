
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
| `/rename <new name>` | Change your user name |
| `/all <msg>` | Send a message to everyone |
| `/msg <user> <msg>` | Send a private message |
| `/room create <name>` | Create a new chat room |
| `/room join <id>` | Join a room by ID |
| `/room mkadmin <user>` | Make a user an admin in the room |
| `/room rmadmin <user>` | Remove a user from admin role |
| `/room leave` | Leave the current room |
| `/room list` | Show all active rooms |
| `/room users` | List users in the current room |
| `/room kick <user>` | Kick the user from the room |
| `/room ban <user>` | Ban the user (by username) from the room |
| `/room banmac <user>` | Ban the user's MAC address from the room |
| `/room bannedmacs` | Show MAC-banned users in the current room |
| `/room unbanmac <user>` | Unban the user's MAC (super admin only) |
| `/room switch <room id>` | Switch to another joined room |
| `/room admins` | Show list of admins in the current room |
| `/room report <user> <reason>` | Report a user in the room |
| `/roomid` | Show current room ID |
| `/achievements` | Show your unlocked achievements |
| `/exit` | Disconnect from the server |
| `/help` | Show this help message |
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


## 📌 Notes

- Messages are real-time and text-based.
- Room messages are only visible to users in that room.
- Server auto-removes users and announces when someone leaves.
