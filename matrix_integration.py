import asyncio
import logging
import os
import json
from urllib.parse import urlparse
from nio import AsyncClient, MatrixRoom, RoomMessageText, LoginResponse, JoinResponse, RoomCreateResponse

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

client = None
config_file = "matrix_config.json"
user_keys = {}  # {"@user:matrix.org": shift_int}
current_room_id = None

# Caesar Cipher
def caesar_encrypt(plaintext, shift):
    result = []
    for ch in plaintext:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            result.append(chr((ord(ch) - base + shift) % 26 + base))
        else:
            result.append(ch)
    return ''.join(result)

def caesar_decrypt(ciphertext, shift):
    return caesar_encrypt(ciphertext, -shift)

# Helpers
def is_valid_url(url):
    try:
        result = urlparse(url)
        return result.scheme in ('http', 'https') and result.netloc
    except:
        return False

def load_config():
    if os.path.exists(config_file):
        try:
            with open(config_file, 'r') as f:
                return json.load(f)
        except:
            pass
    return {
        "homeserver": "https://matrix.org",
        "user_id": "",
        "device_id": "",
        "access_token": "",
        "room_id": ""
    }

def save_config(config):
    with open(config_file, 'w') as f:
        json.dump(config, f, indent=4)

# Setup Client & Room
async def setup_client():
    global client, current_room_id
    config = load_config()
    homeserver = config.get('homeserver', 'https://matrix.org')
    if config.get('user_id') and config.get('access_token'):
        client = AsyncClient(homeserver, config['user_id'])
        client.device_id = config['device_id']
        client.access_token = config['access_token']
        client.user_id = config['user_id']
        if config.get('room_id'):
            current_room_id = config['room_id']
        return True

    homeserver_input = input(f"Homeserver [{homeserver}]: ").strip()
    if homeserver_input:
        homeserver = homeserver_input
    while not is_valid_url(homeserver):
        homeserver = input("Enter valid homeserver (e.g. https://matrix.org): ").strip()

    user_id = input("Matrix User ID (e.g., @user:matrix.org): ").strip()
    client = AsyncClient(homeserver, user_id)
    password = input("Password: ").strip()
    try:
        resp = await client.login(password=password, device_name="CaesarDemoDevice")
        if isinstance(resp, LoginResponse):
            config['homeserver'] = homeserver
            config['user_id'] = resp.user_id or user_id
            config['device_id'] = resp.device_id
            config['access_token'] = resp.access_token
            save_config(config)
            client.user_id = config['user_id']
            await setup_room(config)
            return True
        else:
            print(f"Login failed: {resp}")
            return False
    except Exception as e:
        print(f"Login error: {e}")
        return False

async def setup_room(config):
    global current_room_id
    opt = input("Join existing room (j) or create new (c)? [j/c]: ").strip().lower()
    if opt == 'c':
        name = input("Room name: ").strip()
        resp = await client.room_create(name=name)
        if isinstance(resp, RoomCreateResponse):
            current_room_id = resp.room_id
            config['room_id'] = current_room_id
            save_config(config)
            print("Room created:", current_room_id)
    else:
        room = input("Room ID or alias: ").strip()
        resp = await client.join(room)
        if isinstance(resp, JoinResponse):
            current_room_id = resp.room_id
            config['room_id'] = current_room_id
            save_config(config)
            print("Joined room:", current_room_id)

# Messaging
async def message_callback(room: MatrixRoom, event: RoomMessageText):
    try:
        if event.body.startswith("ENC:"):
            ciphertext = event.body[4:]
            uid = event.sender
            if uid in user_keys:
                shift = user_keys[uid]
                plaintext = caesar_decrypt(ciphertext, shift)
                print(f"\n🔓 Decrypted from {uid}: {plaintext}")
            else:
                print(f"\n⚠️  Encrypted from {uid}, no key: {ciphertext}")
        else:
            print(f"\n📨 {event.sender}: {event.body}")
    except Exception as e:
        logger.error(f"Error processing msg: {e}")

async def start_sync():
    if client:
        client.add_event_callback(message_callback, RoomMessageText)
        try:
            while True:
                await client.sync(timeout=30000, full_state=False)
        except KeyboardInterrupt:
            pass

async def send_encrypted_message(message, shift):
    global current_room_id
    if not current_room_id:
        print("No room configured")
        return False
    ciphertext = caesar_encrypt(message, shift)
    resp = await client.room_send(
        room_id=current_room_id,
        message_type="m.room.message",
        content={"msgtype": "m.text", "body": f"ENC:{ciphertext}"}
    )
    if hasattr(resp, 'event_id') and resp.event_id:
        print("✅ Encrypted message sent")
        return True
    return False

# Main Loop
async def main_loop():
    global current_room_id
    if not await setup_client():
        print("Client setup failed.")
        return
    cfg = load_config()
    if not current_room_id and cfg.get('room_id'):
        current_room_id = cfg['room_id']
    asyncio.create_task(start_sync())
    await client.sync(full_state=True)

    while True:
        print("\n=== Caesar Encrypted Matrix Messenger ===")
        print("1. Set Caesar shift for a user")
        print("2. Send encrypted message")
        print("3. Change room")
        print("4. Exit")
        choice = input("Option: ").strip()
        if choice == "1":
            uid = input("Enter user ID: ").strip()
            try:
                shift = int(input("Enter Caesar shift (int): ").strip())
                user_keys[uid] = shift
                print(f"Shift {shift} set for {uid}")
            except ValueError:
                print("Invalid shift.")
        elif choice == "2":
            if not user_keys:
                print("No keys set.")
                continue
            if not current_room_id:
                print("No room configured.")
                continue
            msg = input("Message: ").strip()
            uid, shift = list(user_keys.items())[0]
            await send_encrypted_message(msg, shift)
        elif choice == "3":
            await setup_room(load_config())
        elif choice == "4":
            print("Exiting...")
            if client:
                await client.close()
            break
        else:
            print("Invalid option")

if __name__ == "__main__":
    try:
        asyncio.run(main_loop())
    except KeyboardInterrupt:
        print("Exiting...")
    finally:
        if client:
            asyncio.run(client.close())