#!/usr/bin/env python3
"""
SSH Honeypot - Paramiko-based SSH server that logs attacker activity
Educational and research purposes only.
"""

import socket
import threading
import json
import os
import time
from datetime import datetime

# Try to import required modules
try:
    import paramiko
except ImportError:
    print("Error: paramiko not installed. Install with: pip install paramiko")
    exit(1)

# ---------------- CONFIG ----------------
PORT = 2222
BASE_DIR = "/opt/ssh-honeypot"
LOG_DIR = f"{BASE_DIR}/logs"
KEY_PATH = f"{BASE_DIR}/ssh_host_rsa_key"
LOG_FILE = f"{LOG_DIR}/sessions.json"

# Fake filesystem structure
FAKE_FS = {
    "/": ["bin", "etc", "home", "var", "usr", "tmp"],
    "/bin": ["bash", "ls", "cat", "pwd", "whoami"],
    "/etc": ["passwd", "shadow", "ssh", "hosts", "network"],
    "/home": ["root", "admin", "user"],
    "/var": ["log", "www", "lib"],
    "/tmp": [],
    "/usr": ["bin", "lib", "share"],
}

# Common fake commands and their responses
COMMAND_RESPONSES = {
    "uname -a": "Linux ubuntu 5.15.0-84-generic #94-Ubuntu SMP Thu Aug 4 20:51:32 UTC 2022 x86_64 x86_64 x86_64 GNU/Linux\n",
    "cat /etc/passwd": """root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
""",
    "cat /etc/hosts": """127.0.0.1 localhost
127.0.1.1 ubuntu

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
""",
    "whoami": "",  # Will be replaced with actual username
    "pwd": "",     # Will be replaced with current directory
    "ls": "",      # Will be replaced with directory listing
}

# ----------------------------------------

def setup_environment():
    """Create necessary directories and files."""
    os.makedirs(LOG_DIR, exist_ok=True)
    return True

def generate_or_load_host_key():
    """Generate new RSA key or load existing one."""
    if os.path.exists(KEY_PATH):
        print(f"[+] Loading existing host key from {KEY_PATH}")
        return paramiko.RSAKey(filename=KEY_PATH)
    else:
        print(f"[+] Generating new host key at {KEY_PATH}")
        key = paramiko.RSAKey.generate(2048)
        key.write_private_key_file(KEY_PATH)
        return key

def log_event(data):
    """Append session data to JSON log file."""
    try:
        with open(LOG_FILE, "a") as f:
            f.write(json.dumps(data, default=str) + "\n")
        return True
    except Exception as e:
        print(f"[!] Failed to log event: {e}")
        return False

class HoneypotServer(paramiko.ServerInterface):
    """SSH server implementation that accepts all connections."""
    
    def __init__(self, client_ip):
        self.client_ip = client_ip
        self.username = None
        self.password = None
        self.authenticated_time = None

    def check_auth_password(self, username, password):
        """Accept any username/password combination."""
        self.username = username
        self.password = password
        self.authenticated_time = datetime.now()
        
        # Log authentication attempt immediately
        auth_log = {
            "timestamp": str(datetime.now()),
            "event": "auth_attempt",
            "ip": self.client_ip,
            "username": username,
            "password": password
        }
        log_event(auth_log)
        
        print(f"[+] Auth attempt: {self.client_ip} - {username}:{password}")
        return paramiko.AUTH_SUCCESSFUL

    def check_channel_request(self, kind, chanid):
        """Allow session channels only."""
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_shell_request(self, channel):
        """Allow shell requests."""
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        """Allow PTY requests."""
        return True

def normalize_path(cwd, target):
    """Normalize a path relative to current directory."""
    if not target:
        return "/"
    
    # Handle absolute paths
    if target.startswith("/"):
        path = target
    else:
        path = os.path.join(cwd, target)
    
    # Normalize path
    normalized = os.path.normpath(path)
    
    # Ensure it starts with /
    if not normalized.startswith("/"):
        normalized = "/" + normalized
    
    return normalized

def handle_command(channel, command, cwd, session_data):
    """Process and respond to a command."""
    command = command.strip()
    
    # Add to session log
    session_data["commands"].append({
        "timestamp": str(datetime.now()),
        "command": command,
        "cwd": cwd
    })
    
    # Handle exit
    if command == "exit" or command == "logout":
        channel.send("logout\n")
        return None, "exit"
    
    # Handle clear
    elif command == "clear":
        channel.send("\033[H\033[J")
        return cwd, None
    
    # Handle pwd
    elif command == "pwd":
        channel.send(cwd + "\n")
        return cwd, None
    
    # Handle cd
    elif command.startswith("cd"):
        parts = command.split()
        if len(parts) == 1:
            new_cwd = "/"
        else:
            target = parts[1]
            new_cwd = normalize_path(cwd, target)
            
            # Check if path exists in fake filesystem
            if new_cwd in FAKE_FS:
                pass  # Valid directory
            else:
                # Try parent directory
                parent = os.path.dirname(new_cwd)
                if parent in FAKE_FS and new_cwd.split('/')[-1] in FAKE_FS.get(parent, []):
                    pass  # Valid subdirectory
                else:
                    channel.send(f"bash: cd: {target}: No such file or directory\n")
                    return cwd, None
        
        return new_cwd, None
    
    # Handle ls
    elif command == "ls":
        if cwd in FAKE_FS:
            items = FAKE_FS[cwd]
            if items:
                # Format with columns
                output = ""
                for i, item in enumerate(items):
                    output += f"{item:<15}"
                    if (i + 1) % 4 == 0:
                        output += "\n"
                if output and not output.endswith("\n"):
                    output += "\n"
                channel.send(output)
            else:
                channel.send("\n")  # Empty directory
        else:
            channel.send("ls: cannot access directory: No such file or directory\n")
        return cwd, None
    
    # Handle whoami
    elif command == "whoami":
        channel.send(session_data.get("username", "unknown") + "\n")
        return cwd, None
    
    # Handle help
    elif command == "help":
        help_text = """Available commands:
  ls                    List directory contents
  cd <dir>              Change directory
  pwd                   Print working directory
  whoami                Print current user
  cat <file>            Display file contents
  uname -a              Show system information
  exit                  Logout
  clear                 Clear screen
  help                  Show this help
"""
        channel.send(help_text)
        return cwd, None
    
    # Handle predefined responses
    elif command in COMMAND_RESPONSES:
        response = COMMAND_RESPONSES[command]
        if command == "whoami":
            response = session_data.get("username", "unknown") + "\n"
        channel.send(response)
        return cwd, None
    
    # Handle cat command
    elif command.startswith("cat "):
        parts = command.split()
        if len(parts) >= 2:
            filename = parts[1]
            if filename == "/etc/passwd":
                channel.send(COMMAND_RESPONSES["cat /etc/passwd"])
            elif filename == "/etc/hosts":
                channel.send(COMMAND_RESPONSES["cat /etc/hosts"])
            else:
                channel.send(f"cat: {filename}: No such file or directory\n")
        else:
            channel.send("cat: missing file operand\n")
        return cwd, None
    
    # Unknown command
    else:
        channel.send(f"bash: {command}: command not found\n")
        return cwd, None

def handle_connection(client, addr):
    """Handle a single SSH connection."""
    client_ip = addr[0]
    print(f"[+] New connection from {client_ip}:{addr[1]}")
    
    transport = None
    try:
        transport = paramiko.Transport(client)
        transport.add_server_key(HOST_KEY)
        
        server = HoneypotServer(client_ip)
        
        # Start SSH server
        transport.start_server(server=server)
        
        # Wait for channel
        channel = transport.accept(20)
        if not channel:
            print(f"[-] No channel created for {client_ip}")
            return
        
        # Create session data
        session_id = int(time.time() * 1000)
        session_data = {
            "session_id": session_id,
            "start_time": str(datetime.now()),
            "ip": client_ip,
            "port": addr[1],
            "username": server.username,
            "password": server.password,
            "commands": []
        }
        
        # Send welcome message
        welcome = f"""
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.15.0-84-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

System information as of {datetime.now().strftime('%a %b %d %H:%M:%S UTC %Y')}

Last login: {datetime.now().strftime('%a %b %d %H:%M:%S')} from 192.168.1.100

"""
        channel.send(welcome)
        
        # Main shell loop
        cwd = "/"
        channel.send(f"{server.username}@{'ubuntu'}:{cwd}$ ")
        
        while True:
            try:
                # Receive command
                data = channel.recv(1024)
                if not data:
                    break
                
                command = data.decode('utf-8', errors='ignore').strip()
                if not command:
                    channel.send(f"{server.username}@{'ubuntu'}:{cwd}$ ")
                    continue
                
                # Handle command
                new_cwd, action = handle_command(channel, command, cwd, session_data)
                
                if action == "exit":
                    break
                
                if new_cwd:
                    cwd = new_cwd
                
                # Send prompt
                channel.send(f"{server.username}@{'ubuntu'}:{cwd}$ ")
                
            except EOFError:
                break
            except Exception as e:
                print(f"[!] Error handling command from {client_ip}: {e}")
                break
        
        # Log session
        session_data["end_time"] = str(datetime.now())
        session_data["cwd"] = cwd
        log_event(session_data)
        
        print(f"[+] Session ended for {client_ip}")
        
    except paramiko.SSHException as e:
        print(f"[-] SSH negotiation failed for {client_ip}: {e}")
    except Exception as e:
        print(f"[-] Connection error for {client_ip}: {e}")
    finally:
        try:
            if transport:
                transport.close()
        except:
            pass
        client.close()

def main():
    """Main honeypot server loop."""
    print(f"[+] Starting SSH Honeypot on port {PORT}")
    print(f"[+] Logs will be saved to {LOG_FILE}")
    print(f"[+] Host key: {KEY_PATH}")
    print("[+] Accepting all connections...")
    print("[+] Press Ctrl+C to stop\n")
    
    # Setup environment
    if not setup_environment():
        print("[-] Failed to setup environment")
        return
    
    # Generate/Load host key
    global HOST_KEY
    HOST_KEY = generate_or_load_host_key()
    
    # Create and configure socket
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(1)  # Allows for KeyboardInterrupt checking
        
        sock.bind(("0.0.0.0", PORT))
        sock.listen(100)
        
        print(f"[✓] Listening on 0.0.0.0:{PORT}")
        
        # Main accept loop
        while True:
            try:
                client, addr = sock.accept()
                client.settimeout(30)  # Set timeout on client socket
                
                # Handle connection in separate thread
                thread = threading.Thread(
                    target=handle_connection,
                    args=(client, addr),
                    daemon=True
                )
                thread.start()
                
            except socket.timeout:
                continue  # Just timeout, continue accepting
            except KeyboardInterrupt:
                print("\n[!] Received shutdown signal")
                break
            except Exception as e:
                print(f"[!] Accept error: {e}")
                continue
                
    except KeyboardInterrupt:
        print("\n[!] Shutting down honeypot...")
    except Exception as e:
        print(f"[!] Fatal error: {e}")
    finally:
        if sock:
            sock.close()
        print("[+] Honeypot stopped")

if __name__ == "__main__":
    main()