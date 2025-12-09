import socket
import threading
from datetime import datetime
from cryptography.fernet import Fernet
from collections import deque

HOST = "127.0.0.1"  #localhost
PORT = 65432        #available port

# Message log storage (keep last 1000 messages)
message_logs = deque(maxlen=1000)
server_start_time = None

# Generate encryption key (in production, this should be securely stored)
ENCRYPTION_KEY = Fernet.generate_key()
cipher_suite = Fernet(ENCRYPTION_KEY)

#Create arrays to keep track of usernames with client connections
clients = []
usernames = []
# Dictionary mapping username to client socket
username_to_client = {}
# Dictionary mapping username to set of blocked usernames
blocked_users = {}
# Dictionary mapping group name to set of usernames
groups = {}
# Dictionary mapping username to set of groups they're in
user_groups = {}

#Function to encrypt and send message
def send_encrypted(client, message):
    """Send encrypted message to client. Returns True if successful, False otherwise."""
    try:
        encrypted = cipher_suite.encrypt(message.encode('utf-8'))
        # Send length first, then encrypted data
        client.send(len(encrypted).to_bytes(4, 'big'))
        client.send(encrypted)
        return True
    except (ConnectionResetError, ConnectionAbortedError, OSError, BrokenPipeError) as e:
        # Connection closed by client - don't log, just return False
        return False
    except Exception as e:
        # Other errors - log but don't spam
        return False

#Function to receive and decrypt message
def receive_decrypted(client):
    try:
        # Receive length
        length_bytes = client.recv(4)
        if not length_bytes or len(length_bytes) == 0:
            return None
        length = int.from_bytes(length_bytes, 'big')
        # Receive encrypted data
        encrypted = b''
        while len(encrypted) < length:
            chunk = client.recv(length - len(encrypted))
            if not chunk:
                return None
            encrypted += chunk
        # Decrypt
        decrypted = cipher_suite.decrypt(encrypted)
        return decrypted.decode('utf-8')
    except (ConnectionResetError, ConnectionAbortedError, OSError) as e:
        # Connection closed by client
        return None
    except Exception as e:
        # Other decryption errors - likely connection issue
        return None

#Function to organize the broadcast functionality of the server
#   Sends the message to all clients except the sender.
def broadcast(message, sender_socket=None, sender_username=None):
    sender_index = None
    if sender_socket:
        try:
            sender_index = clients.index(sender_socket)
            sender_username = usernames[sender_index]
        except:
            pass
    
    # Create a copy of the list to iterate over, as it may change during iteration
    clients_to_check = list(clients)
    
    for i, client in enumerate(clients_to_check):
        # Skip if client was removed
        if client not in clients:
            continue
            
        if client != sender_socket:
            try:
                client_index = clients.index(client)
                username = usernames[client_index]
            except (ValueError, IndexError):
                # Client was removed, skip
                continue
            
            # Check if sender is blocked by this user
            if sender_username and username in blocked_users:
                if sender_username in blocked_users[username]:
                    continue  # Skip sending to users who blocked the sender
            
            # Try to send, and remove client if send fails
            if not send_encrypted(client, message):
                # Send failed - client is disconnected, remove it
                remove_client(client)




#Function to log messages
def log_message(message_type, sender, content, recipient=None, group=None):
    log_entry = {
        "timestamp": datetime.now().isoformat(),
        "type": message_type,  # "server", "dm", "group", "system"
        "sender": sender,
        "content": content,
        "recipient": recipient,
        "group": group
    }
    message_logs.append(log_entry)
    return log_entry

#Function to handle removing clients from the server
def remove_client(client):
    username = None
    if client in clients:
        try:
            #initialize an index variable to compare with the usernames array
            index = clients.index(client)
            username = usernames[index]

            #removes the client and username from their corresponding arrays
            clients.remove(client)
            usernames.remove(username)
            
            # Remove from username_to_client mapping
            if username in username_to_client:
                del username_to_client[username]
            
            # Remove user from all groups
            if username in user_groups:
                for group_name in list(user_groups[username]):
                    leave_group(username, group_name)
                del user_groups[username]
            
            # Remove blocked users entry
            if username in blocked_users:
                del blocked_users[username]

            # Log disconnect event
            log_message("system", "SERVER", f"{username} has disconnected", recipient=None, group=None)
            
            #broadcast to connected users that a user has disconnected
            # Don't pass the disconnected client as sender_socket
            broadcast(f"[SERVER] {username} has Disconnected!\n", sender_socket=None, sender_username=None)
            
            print(f"[USER DISCONNECTED] {username}")
        except (ValueError, IndexError) as e:
            # Client already removed or not in list
            pass
        except Exception as e:
            print(f"[ERROR] Error removing client: {e}")
    
    #close the connection to the client
    try:
        client.close()
    except:
        pass




#Function to send direct message
def send_direct_message(sender_username, recipient_username, message):
    if recipient_username not in username_to_client:
        return f"[SERVER] User '{recipient_username}' is not online."
    
    recipient_client = username_to_client[recipient_username]
    
    # Check if sender is blocked by recipient
    if recipient_username in blocked_users:
        if sender_username in blocked_users[recipient_username]:
            return f"[SERVER] Cannot send message. You are blocked by {recipient_username}."
    
    timestamp = datetime.now().strftime("%H:%M:%S")
    formatted = f"[{timestamp}] [DM] {sender_username}: {message}"
    
    # Log the message
    log_message("dm", sender_username, message, recipient=recipient_username)
    
    # Try to send, remove client if disconnected
    if send_encrypted(recipient_client, formatted):
        return f"[SERVER] Message sent to {recipient_username}."
    else:
        # Client disconnected, remove them
        if recipient_client in clients:
            remove_client(recipient_client)
        return f"[SERVER] User '{recipient_username}' disconnected. Message not delivered."

#Function to send group message
def send_group_message(sender_username, group_name, message):
    if group_name not in groups:
        return f"[SERVER] Group '{group_name}' does not exist."
    
    if sender_username not in user_groups or group_name not in user_groups[sender_username]:
        return f"[SERVER] You are not a member of group '{group_name}'."
    
    timestamp = datetime.now().strftime("%H:%M:%S")
    formatted = f"[{timestamp}] [GROUP:{group_name}] {sender_username}: {message}"
    
    # Log the message
    log_message("group", sender_username, message, group=group_name)
    
    sent_count = 0
    disconnected_members = []
    
    # Create a copy of group members to iterate over (list may change)
    group_members = list(groups[group_name])
    
    for member_username in group_members:
        if member_username == sender_username:
            continue
        if member_username not in username_to_client:
            continue
        # Check if sender is blocked
        if member_username in blocked_users:
            if sender_username in blocked_users[member_username]:
                continue
        
        member_client = username_to_client[member_username]
        # Try to send, track disconnected clients
        if send_encrypted(member_client, formatted):
            sent_count += 1
        else:
            # Client disconnected, mark for removal
            if member_client in clients:
                disconnected_members.append(member_client)
    
    # Remove disconnected clients
    for client in disconnected_members:
        if client in clients:
            remove_client(client)
    
    return f"[SERVER] Message sent to {sent_count} member(s) in group '{group_name}'."

#Function to create or join a group
def join_group(username, group_name):
    if group_name not in groups:
        groups[group_name] = set()
    
    groups[group_name].add(username)
    
    if username not in user_groups:
        user_groups[username] = set()
    user_groups[username].add(group_name)
    
    return f"[SERVER] You joined group '{group_name}'."

#Function to leave a group
def leave_group(username, group_name):
    if group_name in groups and username in groups[group_name]:
        groups[group_name].remove(username)
        if len(groups[group_name]) == 0:
            del groups[group_name]
    
    if username in user_groups and group_name in user_groups[username]:
        user_groups[username].remove(group_name)
        if len(user_groups[username]) == 0:
            del user_groups[username]
    
    return f"[SERVER] You left group '{group_name}'."

#Function to block a user
def block_user(username, target_username):
    if target_username not in username_to_client:
        return f"[SERVER] User '{target_username}' is not online."
    
    if username not in blocked_users:
        blocked_users[username] = set()
    
    blocked_users[username].add(target_username)
    return f"[SERVER] You have blocked {target_username}."

#Function to unblock a user
def unblock_user(username, target_username):
    if username in blocked_users and target_username in blocked_users[username]:
        blocked_users[username].remove(target_username)
        if len(blocked_users[username]) == 0:
            del blocked_users[username]
        return f"[SERVER] You have unblocked {target_username}."
    return f"[SERVER] {target_username} is not in your blocked list."

#Function to handle communication from individual clients
def handle_client(client):
    username = None
    # Get username at start for logging purposes
    try:
        if client in clients:
            index = clients.index(client)
            username = usernames[index]
    except:
        pass
    
    while True:
        try:
            message = receive_decrypted(client)
            if not message:
                # Connection closed - no data received
                if username:
                    print(f"[CONNECTION CLOSED] {username} disconnected (no data)")
                remove_client(client)
                break

            #get the index and username of the current client
            try:
                index = clients.index(client)
                username = usernames[index]
            except (ValueError, IndexError):
                # Client was removed, exit loop
                break

            # Parse context-based messages (from client context switching)
            if message.startswith('__DM__'):
                # Format: __DM__<username>__<message>
                parts = message.split('__', 3)
                if len(parts) >= 4:
                    recipient = parts[2]
                    dm_message = parts[3]
                    response = send_direct_message(username, recipient, dm_message)
                    send_encrypted(client, response)
                continue
            elif message.startswith('__GROUP__'):
                # Format: __GROUP__<groupname>__<message>
                parts = message.split('__', 3)
                if len(parts) >= 4:
                    group_name = parts[2]
                    group_message = parts[3]
                    response = send_group_message(username, group_name, group_message)
                    send_encrypted(client, response)
                continue
            
            # Parse commands
            if message.startswith('/'):
                parts = message.split(' ', 2)
                command = parts[0].lower()
                
                if command == '/dm' and len(parts) >= 3:
                    recipient = parts[1]
                    dm_message = parts[2]
                    response = send_direct_message(username, recipient, dm_message)
                    send_encrypted(client, response)
                    
                elif command == '/group' and len(parts) >= 3:
                    group_name = parts[1]
                    group_message = parts[2]
                    response = send_group_message(username, group_name, group_message)
                    send_encrypted(client, response)
                    
                elif command == '/join' and len(parts) >= 2:
                    group_name = parts[1]
                    response = join_group(username, group_name)
                    send_encrypted(client, response)
                    
                elif command == '/leave' and len(parts) >= 2:
                    group_name = parts[1]
                    response = leave_group(username, group_name)
                    send_encrypted(client, response)
                    
                elif command == '/block' and len(parts) >= 2:
                    target_username = parts[1]
                    response = block_user(username, target_username)
                    send_encrypted(client, response)
                    
                elif command == '/unblock' and len(parts) >= 2:
                    target_username = parts[1]
                    response = unblock_user(username, target_username)
                    send_encrypted(client, response)
                    
                elif command == '/blocked':
                    if username in blocked_users and len(blocked_users[username]) > 0:
                        blocked_list = ', '.join(blocked_users[username])
                        response = f"[SERVER] Blocked users: {blocked_list}"
                    else:
                        response = "[SERVER] You have no blocked users."
                    send_encrypted(client, response)
                    
                elif command == '/groups':
                    if username in user_groups and len(user_groups[username]) > 0:
                        group_list = ', '.join(user_groups[username])
                        response = f"[SERVER] Your groups: {group_list}"
                    else:
                        response = "[SERVER] You are not in any groups."
                    send_encrypted(client, response)
                    
                elif command == '/users':
                    online_users = [u for u in usernames if u != username]
                    if online_users:
                        user_list = ', '.join(online_users)
                        response = f"[SERVER] Online users: {user_list}"
                    else:
                        response = "[SERVER] No other users online."
                    send_encrypted(client, response)
                    
                elif command == '/help':
                    help_text = """[SERVER] Available commands:
/dm <username> - Switch to DM mode with user (then just type messages)
/group <groupname> - Switch to group mode (then just type messages)
/server or /broadcast - Switch back to server chat mode
/context or /mode - Show current messaging context
/join <groupname> - Join or create a group
/leave <groupname> - Leave a group
/block <username> - Block a user
/unblock <username> - Unblock a user
/blocked - List blocked users
/groups - List your groups
/users - List online users
/help - Show this help message
/quit - Disconnect from server

Note: Once in DM or group mode, just type messages normally.
No need to repeat /dm or /group commands!"""
                    send_encrypted(client, help_text)
                else:
                    send_encrypted(client, "[SERVER] Unknown command. Type /help for available commands.")
            else:
                # Regular broadcast message
                timestamp = datetime.now().strftime("%H:%M:%S")
                formatted = f"[{timestamp}] {username}: {message}"

                # Log the message
                log_message("server", username, message)

                #logs the formatted strip for just the server
                print(formatted.strip())

                #calls the broadcast function with the formatted message and sets the current client as the sender
                broadcast(formatted, sender_socket=client, sender_username=username)
        except (ConnectionResetError, ConnectionAbortedError, OSError, BrokenPipeError) as e:
            # Connection closed by client - handle gracefully
            username = None
            try:
                if client in clients:
                    index = clients.index(client)
                    username = usernames[index]
            except:
                pass
            if username:
                print(f"[CONNECTION CLOSED] {username} disconnected")
            # Remove client immediately
            remove_client(client)
            break
        except Exception as e:
            username = None
            try:
                if client in clients:
                    index = clients.index(client)
                    username = usernames[index]
            except:
                pass
            if username:
                print(f"[ERROR] Error handling client {username}: {e}")
            # Remove client immediately
            remove_client(client)
            break




#Function to handle server startup
def start_server():
    global server_start_time
    server_start_time = datetime.now()
    
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Allow port reuse
    server.bind((HOST,PORT))
    server.listen()

    #server log that the server has started on {HOST}:{PORT}
    print(f"[SERVER] Chat server listening on {HOST}:{PORT}")
    print(f"[SERVER] Waiting for client connections...")
    print(f"[SERVER] (This terminal is for server logs only - connect using chat_client.py)")
    log_message("system", "SERVER", f"Server started on {HOST}:{PORT}")

    #accept client connections
    while True:
        client, address = server.accept()
        
        #log connection
        print(f"[NEW CONNECTION] {address} connected!")

        # Send encryption key to client first
        try:
            client.send(len(ENCRYPTION_KEY).to_bytes(4, 'big'))
            client.send(ENCRYPTION_KEY)
        except:
            print(f"[ERROR] Failed to send encryption key to {address}")
            client.close()
            continue
        
        #establish username
        send_encrypted(client, "Enter a username:")
        username = receive_decrypted(client)
        if not username:
            client.close()
            continue
        
        # Check if username already exists
        if username in username_to_client:
            send_encrypted(client, "[SERVER] Username already taken. Connection closed.")
            client.close()
            continue
        
        usernames.append(username)
        clients.append(client)
        username_to_client[username] = client
        blocked_users[username] = set()
        user_groups[username] = set()

        #log new user
        print(f"[USER JOINED] {username}")
        
        # Log user join event
        log_message("system", "SERVER", f"{username} has joined the chat")

        #broadcast to current users that a new user has joined the chat
        broadcast(f"[SERVER] {username} has joined the chat!\n", sender_socket=client)
        send_encrypted(client, f"Welcome {username}! Type /help for available commands.")

        thread = threading.Thread(target=handle_client, args=(client,))
        thread.start()





if __name__ == "__main__":
    print("=" * 60)
    print("Chat Server")
    print("=" * 60)
    print(f"[INFO] Starting chat server...")
    print(f"[INFO] Chat server will listen on {HOST}:{PORT}")
    print(f"[INFO] Connect clients using: python chat_client.py")
    print(f"[INFO] Press Ctrl+C to stop the server\n")
    print("=" * 60)
    
    start_server()