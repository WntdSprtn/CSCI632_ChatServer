import socket
import threading
import sys
from cryptography.fernet import Fernet

HOST = "127.0.0.1"  #localhost
PORT = 65432        #available port

# Encryption key (must match server - in production, use proper key exchange)
# For this implementation, we'll receive it from server during handshake
ENCRYPTION_KEY = None
cipher_suite = None

# Context tracking for messaging modes
current_mode = "server"  # "server", "dm", or "group"
current_target = None  # username for DM mode, groupname for group mode



#setup the client socket and connection
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    client.connect((HOST,PORT))
except:
    print("[ERROR] Could not connect to the server.")
    sys.exit





#Function to send encrypted message
def send_encrypted(message):
    try:
        encrypted = cipher_suite.encrypt(message.encode('utf-8'))
        # Send length first, then encrypted data
        client.send(len(encrypted).to_bytes(4, 'big'))
        client.send(encrypted)
    except Exception as e:
        print(f"[ERROR] Failed to send encrypted message: {e}")

#Function to receive and decrypt message
def receive_decrypted():
    try:
        # Receive length
        length_bytes = client.recv(4)
        if not length_bytes:
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
    except Exception as e:
        print(f"[ERROR] Failed to decrypt message: {e}")
        return None

#function to constantly listen for any messages to receive
def receive_message():
    global cipher_suite, ENCRYPTION_KEY
    
    # First, receive encryption key from server
    try:
        key_length_bytes = client.recv(4)
        if not key_length_bytes:
            print("[ERROR] Failed to receive encryption key.")
            return
        key_length = int.from_bytes(key_length_bytes, 'big')
        ENCRYPTION_KEY = client.recv(key_length)
        cipher_suite = Fernet(ENCRYPTION_KEY)
        print("[INFO] Encryption established with server.")
    except Exception as e:
        print(f"[ERROR] Failed to establish encryption: {e}")
        client.close()
        return
    
    while True:
        try:
            #decode and check what message is recieved and whether the server needs a response or not
            message = receive_decrypted()
            if not message:
                break

            if message == "Enter a username:":
                send_encrypted(username)
            else:
                print(message)
        
        #close socket if the connection to the server is lost
        except Exception as e:
            print(f"[ERROR] Connection lost: {e}")
            client.close()
            break





#function to get the prompt based on current context
def get_prompt():
    global current_mode, current_target
    if current_mode == "dm":
        return f"[DM:{current_target}] "
    elif current_mode == "group":
        return f"[GROUP:{current_target}] "
    else:
        return "[SERVER] "

#function to send any messages type into the terminal
def send_message():
    global current_mode, current_target
    
    # Wait for encryption to be established
    import time
    while cipher_suite is None:
        time.sleep(0.1)
    
    print(f"\n{get_prompt()}", end="", flush=True)
    
    while True:
        try:
            message = input("")

            #allows the client to leave the chat server with a command
            if message.lower() == '/quit':
                client.close()
                sys.exit()
            
            # Handle context switching commands
            if message.startswith('/'):
                parts = message.split(' ', 1)
                command = parts[0].lower()
                
                if command == '/dm' and len(parts) >= 2:
                    current_mode = "dm"
                    current_target = parts[1]
                    print(f"[INFO] Switched to DM mode with {current_target}")
                    print(f"{get_prompt()}", end="", flush=True)
                    continue
                    
                elif command == '/group' and len(parts) >= 2:
                    current_mode = "group"
                    current_target = parts[1]
                    # Send join command to server
                    send_encrypted(f"/join {current_target}")
                    print(f"[INFO] Switched to group mode: {current_target}")
                    print(f"{get_prompt()}", end="", flush=True)
                    continue
                    
                elif command == '/server' or command == '/broadcast':
                    current_mode = "server"
                    current_target = None
                    print(f"[INFO] Switched to server chat mode")
                    print(f"{get_prompt()}", end="", flush=True)
                    continue
                    
                elif command == '/context' or command == '/mode':
                    print(f"[INFO] Current mode: {current_mode}" + (f" (target: {current_target})" if current_target else ""))
                    print(f"{get_prompt()}", end="", flush=True)
                    continue
                
                # Pass other commands through to server
                send_encrypted(message)
                continue
            
            # Route message based on current context
            if current_mode == "dm" and current_target:
                # Send as DM
                send_encrypted(f"__DM__{current_target}__{message}")
            elif current_mode == "group" and current_target:
                # Send as group message
                send_encrypted(f"__GROUP__{current_target}__{message}")
            else:
                # Send as server broadcast
                send_encrypted(message)
            
            # Show prompt for next message
            print(f"{get_prompt()}", end="", flush=True)
        except Exception as e:
            print(f"[ERROR] Failed to send message: {e}")
            break




#setup client username
username = input("Enter your username: ")

#start threads
receive_thread = threading.Thread(target=receive_message)
receive_thread.start()

send_thread = threading.Thread(target=send_message)
send_thread.start()