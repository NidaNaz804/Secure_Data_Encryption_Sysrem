import streamlit as st
import hashlib
import json
import os
import time
from cryptography.fernet import Fernet
from base64 import urlsafe_b64encode
from hashlib import pbkdf2_hmac

# Constants
DATA_FILE = "secure_data.json"
SALT = b"ultra_secure_salt_value"
LOCKOUT_DURATION = 60

# Session state management
if "authenticated_user" not in st.session_state:
    st.session_state.authenticated_user = None
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0
if "lockout_time" not in st.session_state:
    st.session_state.lockout_time = 0

# Load & Save functions
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return {}

def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f, indent=2)

# Key generation
def generate_key(passkey):
    key = pbkdf2_hmac('sha256', passkey.encode(), SALT, 100000)
    return urlsafe_b64encode(key)

def hash_password(password):
    return hashlib.pbkdf2_hmac('sha256', password.encode(), SALT, 100000).hex()

# Encryption & Decryption
def encrypt_text(text, key):
    cipher = Fernet(generate_key(key))
    return cipher.encrypt(text.encode()).decode()

def decrypt_text(encrypted_text, key):
    try:
        cipher = Fernet(generate_key(key))
        return cipher.decrypt(encrypted_text.encode()).decode()
    except:
        return None

# Data loading
stored_data = load_data()

# Navigation
st.title("🔒EncryptoVault: Protect Your Secrets")
menu = ["🏠 Dashboard", "📝 Sign Up", "🔐 Sign In", "💾 Secure Save", "🔓 Unlock Data"]
choice = st.sidebar.radio("Navigate", menu)

# Home
if choice == "🏠 Dashboard":
    st.subheader("Welcome to EncryptoVault! 🔐")
    st.markdown("""
    Keep your data safe using encryption technology.
    - 🔑 Each entry is locked with your private key
    - 🧠 Password attempts are limited to protect your vault
    - 💡 Simple Streamlit interface, no external database needed
    """)

# Register
elif choice == "📝 Sign Up":
    st.subheader("Create a New Account 🧾")
    username = st.text_input("Choose a Username")
    password = st.text_input("Set a Strong Password", type="password")

    if st.button("Create Account"):
        if username and password:
            if username in stored_data:
                st.warning("🚫 Username already exists. Try logging in.")
            else:
                stored_data[username] = {
                    "password": hash_password(password),
                    "data": []
                }
                save_data(stored_data)
                st.success("🎉 Registration successful! You can now sign in.")
        else:
            st.error("⚠️ Please fill in all fields.")

# Login
elif choice == "🔐 Sign In":
    st.subheader("Access Your Vault 🔓")

    if time.time() < st.session_state.lockout_time:
        wait_time = int(st.session_state.lockout_time - time.time())
        st.error(f"⏳ Too many attempts. Try again in {wait_time} seconds.")
        st.stop()

    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        if username in stored_data and stored_data[username]["password"] == hash_password(password):
            st.session_state.authenticated_user = username
            st.session_state.failed_attempts = 0
            st.success(f"👋 Welcome back, {username}!")
        else:
            st.session_state.failed_attempts += 1
            remaining = 3 - st.session_state.failed_attempts
            st.error(f"❌ Invalid login. Attempts left: {remaining}")

            if st.session_state.failed_attempts >= 3:
                st.session_state.lockout_time = time.time() + LOCKOUT_DURATION
                st.error("🔒 Account temporarily locked for 60 seconds.")
                st.stop()

# Store Data
elif choice == "💾 Secure Save":
    if not st.session_state.authenticated_user:
        st.warning("⚠️ Please log in to access this feature.")
    else:
        st.subheader("Encrypt & Save Your Secret 🛡️")
        secret_data = st.text_area("Enter your confidential data")
        passkey = st.text_input("Enter a passkey (your private key)", type="password")

        if st.button("Encrypt & Store"):
            if secret_data and passkey:
                encrypted = encrypt_text(secret_data, passkey)
                stored_data[st.session_state.authenticated_user]["data"].append(encrypted)
                save_data(stored_data)
                st.success("🔐 Your data has been securely saved!")
            else:
                st.error("❗ All fields are required.")

# Retrieve Data
elif choice == "🔓 Unlock Data":
    if not st.session_state.authenticated_user:
        st.warning("⚠️ Please log in to access this feature.")
    else:
        st.subheader("Retrieve and Decrypt Your Info 🔍")
        user_data = stored_data.get(st.session_state.authenticated_user, {}).get("data", [])

        if not user_data:
            st.info("ℹ️ No data entries found.")
        else:
            st.write("📜 Encrypted Entries:")
            for i, entry in enumerate(user_data):
                st.code(entry, language="text")

            encrypted_input = st.text_area("Paste the encrypted text here")
            passkey = st.text_input("Enter your private passkey", type="password")

            if st.button("Decrypt"):
                result = decrypt_text(encrypted_input, passkey)
                if result:
                    st.success(f"🟢 Decrypted Message: {result}")
                else:
                    st.error("🚫 Incorrect passkey or invalid encrypted text.")
