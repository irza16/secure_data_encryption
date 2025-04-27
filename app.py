import streamlit as st
import hashlib
import json
import time
import os
from cryptography.fernet import Fernet
import base64
import secrets

# Load or generate a Fernet key stored in fernet.key file
FERNET_KEY_FILE = "fernet.key"

if not os.path.exists(FERNET_KEY_FILE):
    key = Fernet.generate.key()
    with open(FERNET_KEY_FILE, "wb") as f:
        f.write(key)

else:
    with open(FERNET_KEY_FILE, "rb") as f:
        key = f.read()
        


cipher = Fernet(key) #variable to store the fernet(key) object

# Data file for persistence
DATA_FILE = "data.json"

# Load existing data
if os.path.exists(DATA_FILE):
    with open(DATA_FILE, "r") as f:
        stored_data = json.load(f)
else:
    stored_data = {}  # Structure: {"username": {"password": "hashed", "entries": [{"encrypted_text": "", "passkey": "hashed"}]}}
    
# Failed attempts
failed_attempts = {}
lockout_time = {}

# Security functions
def pbkdf2_hash(text, salt=None):
    if not salt:
        salt = secrets.token_bytes(16)
    hashed = hashlib.pbkdf2_hmac('sha256', text.encode(), salt, 100000)
    return base64.b64encode(salt + hashed).decode()

def verify_pbkdf2_hash(text, hashed_text):
    decoded = base64.b64decode(hashed_text)
    salt = decoded[:16]
    true_hash = decoded[16:]
    new_hash = hashlib.pbkdf2_hmac('sha256', text.encode(), salt, 100000)
    return new_hash == true_hash

# Functions for data operations
def encrypt_data(plain_text):
    return cipher.encrypt(plain_text.encode()).decode()

def decrypt_data(encrypted_text):
    return cipher.decrypt(encrypted_text.encode()).decode()

def save_data():
    with open(DATA_FILE, "w") as f:
        json.dump(stored_data, f)

# App session state
if 'logged_in' not in st.session_state:
    st.session_state.logged_in = False
if 'username' not in st.session_state:
    st.session_state.username = ""

# Streamlit UI
st.title("🔒 Secure Data Encryption System")

menu = ["Home", "Signup", "Login", "Store Data", "Retrieve Data", "Logout"]
choice = st.sidebar.selectbox("Navigation", menu)

# Home
if choice == "Home":
    st.subheader("🏠 Welcome")
    st.write("This app allows you to securely store and retrieve data with encryption and passkey protection.")

# Signup
elif choice == "Signup":
    st.subheader("📝 Create Account")
    username = st.text_input("Choose a Username")
    password = st.text_input("Choose a Password", type="password")
    if st.button("Signup"):
        if username and password:
            if username in stored_data:
                st.error("Username already exists!")
            else:
                hashed_password = pbkdf2_hash(password)
                stored_data[username] = {"password": hashed_password, "entries": []}
                save_data()
                st.success("Account created successfully!")
        else:
            st.error("Please fill all fields.")

# Login
elif choice == "Login":
    st.subheader("🔑 Login")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        if username in stored_data and verify_pbkdf2_hash(password, stored_data[username]["password"]):
            if username in lockout_time and time.time() < lockout_time[username]:
                remaining = int(lockout_time[username] - time.time())
                st.warning(f"⏳ Locked out! Try again in {remaining} seconds.")
            else:
                st.session_state.logged_in = True
                st.session_state.username = username
                failed_attempts[username] = 0
                st.success("Logged in successfully!")
        else:
            st.error("Invalid username or password.")

# Logout
elif choice == "Logout":
    st.session_state.logged_in = False
    st.session_state.username = ""
    st.success("Logged out successfully.")

# Store Data
elif choice == "Store Data":
    if not st.session_state.logged_in:
        st.warning("⚠️ Please login first.")
    else:
        st.subheader("📂 Store New Data")
        data_to_store = st.text_area("Enter your data:")
        passkey = st.text_input("Set a Passkey for this data:", type="password")

        if st.button("Encrypt & Save"):
            if data_to_store and passkey:
                encrypted = encrypt_data(data_to_store)
                hashed_passkey = pbkdf2_hash(passkey)
                stored_data[st.session_state.username]["entries"].append({"encrypted_text": encrypted, "passkey": hashed_passkey})
                save_data()
                st.success("Data stored securely!")
            else:
                st.error("All fields are required.")

# Retrieve Data
elif choice == "Retrieve Data":
    if not st.session_state.logged_in:
        st.warning("⚠️ Please login first.")
    else:
        st.subheader("🔍 Retrieve Your Data")
        user_entries = stored_data[st.session_state.username]["entries"]
        
        if not user_entries:
            st.info("You have no stored data.")
        else:
            selected_entry = st.selectbox("Select an encrypted data", range(len(user_entries)))
            encrypted_text = user_entries[selected_entry]["encrypted_text"]
            st.code(encrypted_text)

            passkey_attempt = st.text_input("Enter the Passkey:", type="password")

            if st.button("Decrypt"):
                if st.session_state.username in lockout_time and time.time() < lockout_time[st.session_state.username]:
                    remaining = int(lockout_time[st.session_state.username] - time.time())
                    st.warning(f"⏳ Locked out! Try again in {remaining} seconds.")
                else:
                    correct_passkey_hash = user_entries[selected_entry]["passkey"]
                    if verify_pbkdf2_hash(passkey_attempt, correct_passkey_hash):
                        failed_attempts[st.session_state.username] = 0
                        decrypted = decrypt_data(encrypted_text)
                        st.success(f"Decrypted Data: {decrypted}")
                    else:
                        failed_attempts[st.session_state.username] = failed_attempts.get(st.session_state.username, 0) + 1
                        remaining = 3 - failed_attempts[st.session_state.username]
                        st.error(f"Wrong passkey! Attempts remaining: {remaining}")
                        
                        if failed_attempts[st.session_state.username] >= 3:
                            lockout_time[st.session_state.username] = time.time() + 120  # 2 minutes lockout
                            st.warning("🔒 Too many failed attempts! Locked for 2 minutes.")

