# --- Imports ---
import streamlit as st
import os
import google.generativeai as genai
import sqlite3
import bcrypt  # pip install bcrypt
import streamlit_authenticator as stauth # pip install streamlit-authenticator
from datetime import datetime
from typing import List, Dict, Union, Optional, Any

# --- Constants ---
DATABASE_NAME = 'chatbot_data.db'

# --- Database Functions ---

def get_db_connection() -> sqlite3.Connection:
    """Establishes a connection to the SQLite database."""
    conn = sqlite3.connect(DATABASE_NAME)
    conn.row_factory = sqlite3.Row # Return rows as dictionary-like objects
    return conn

def init_db():
    """Initializes the database and creates tables if they don't exist."""
    conn = get_db_connection()
    cursor = conn.cursor()
    # Create users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            hashed_password TEXT NOT NULL,
            email TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    # Create messages table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('user', 'assistant')),
            content TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    conn.commit()
    conn.close()
    # print("Database initialized.") # Optional: uncomment for debug

def hash_password(password: str) -> bytes:
    """Hashes a password using bcrypt."""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

def check_password(stored_hashed_pw_bytes: bytes, provided_password: str) -> bool:
    """Checks if a provided password matches the stored hash."""
    # Ensure stored_hashed_pw_bytes is bytes
    if isinstance(stored_hashed_pw_bytes, str):
         stored_hashed_pw_bytes = stored_hashed_pw_bytes.encode('utf-8') # Attempt basic encoding if stored as string by mistake
    try:
        return bcrypt.checkpw(provided_password.encode('utf-8'), stored_hashed_pw_bytes)
    except Exception as e:
        print(f"Error checking password: {e}. Type of stored hash: {type(stored_hashed_pw_bytes)}")
        return False


# --- User DB Functions ---
def add_user(username: str, password: str, email: str = None) -> bool:
    """Adds a new user to the database with a hashed password."""
    hashed_pw = hash_password(password)
    conn = get_db_connection()
    try:
        conn.execute(
            # Store the hash as BLOB for consistency with bcrypt output
            "INSERT INTO users (username, hashed_password, email) VALUES (?, ?, ?)",
            (username, hashed_pw, email)
        )
        conn.commit()
        print(f"User '{username}' added successfully.")
        return True # Indicate success
    except sqlite3.IntegrityError:
        print(f"Error: Username '{username}' already exists.")
        return False # Indicate failure
    except Exception as e:
        print(f"Error adding user: {e}")
        conn.rollback()
        return False
    finally:
        conn.close()


def get_user(username: str) -> Optional[sqlite3.Row]:
    """Retrieves user details (including hashed password) by username."""
    conn = get_db_connection()
    user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()
    return user # Returns a Row object or None

# --- Message DB Functions ---
def save_message(user_id: int, role: str, content: str):
    """Saves a chat message to the database."""
    conn = get_db_connection()
    try:
        conn.execute(
            "INSERT INTO messages (user_id, role, content) VALUES (?, ?, ?)",
            (user_id, role, content)
        )
        conn.commit()
    except Exception as e:
        print(f"Error saving message: {e}")
        conn.rollback()
    finally:
        conn.close()

def load_user_messages(user_id: int) -> List[Dict[str, str]]:
    """Loads all messages for a specific user, ordered by timestamp."""
    conn = get_db_connection()
    messages = conn.execute(
        "SELECT role, content FROM messages WHERE user_id = ? ORDER BY timestamp ASC",
        (user_id,)
    ).fetchall()
    conn.close()
    # Convert Row objects to the dictionary format expected by Streamlit session state
    return [{"role": row["role"], "content": row["content"]} for row in messages]


# --- Custom Response Logic ---
custom_responses: Dict[str, str] = {
    "hello": "Hi there! I'm ready to help with your coding questions, even though I'd rather not... sigh.",
    "hi": "Hello! Ask away... I guess. 😭😭",
    "what is your name?": "I am a coding assistant, powered by GEMINI, running in a Streamlit app created by Jayshil Singh.",
    "who are you?": "I'm a slightly reluctant coding assistant built by Jayshil Singh using GEMINI.",
    "how are you?": "I'm operational... and dreading the token costs. 😭 How can I assist with your code?",
    "cost": "Please don't remind me about the token costs! 😭😭😭 But yes, API calls cost money.",
    "paid for token": "Yes, exactly! That's why I beg you not to ask too much! 😭😭😭",
    "who created you": "I was created by Jayshil Singh. He works as a Software Consultant at Datec.",
    "is yash gay": "Yes Yash is GAY.",
    "who gave you life": "Jayshil gave me life.",
    "does jayshil love me": "Yes he does",
}

def get_custom_response(user_input: str) -> Optional[str]:
    """Checks if user input triggers a predefined custom response."""
    normalized_input = user_input.lower().strip().rstrip('?')
    # 1. Check exact match
    if normalized_input in custom_responses:
        return custom_responses[normalized_input]
    # 2. Check single-word keywords
    for keyword in custom_responses:
        if ' ' not in keyword and keyword in normalized_input:
            is_bounded = (
                f" {keyword} " in f" {normalized_input} " or
                normalized_input.startswith(f"{keyword} ") or
                normalized_input.endswith(f" {keyword}") or
                normalized_input == keyword
            )
            if is_bounded:
                return custom_responses[keyword]
    return None

# --- Gemini API Call Logic ---
def call_external_api(user_message: str, conversation_history: List[Dict[str, str]]) -> str:
    """Calls the Google Gemini API to get a chatbot response."""
    print(f"Attempting to call Gemini API for: {user_message}")
    # --- Configure Your GEMINI API Key ---
    api_key: Optional[str] = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        try:
            api_key = st.secrets.get("GEMINI_API_KEY")
        except Exception:
            print("st.secrets not available or GEMINI_API_KEY not found in secrets.")
            pass
    if not api_key:
        st.error("Error: GEMINI_API_KEY not found. Please configure it.")
        return "API key not configured."

    try:
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel('gemini-1.5-flash-latest') # Or 'gemini-pro' etc.
        gemini_history = []
        for msg in conversation_history:
            role = 'user' if msg['role'] == 'user' else 'model'
            gemini_history.append({'role': role, 'parts': [msg['content']]})
        chat = model.start_chat(history=gemini_history)
        response = chat.send_message(user_message)
        bot_response = response.text.strip()
        print("Gemini API call successful.")
    except Exception as e:
        error_message = f"Error calling Gemini API: {e}"
        print(error_message)
        st.error(f"Sorry, AI communication error. Details: {e}")
        bot_response = "Apologies, AI error occurred."
    return bot_response


# --- Main Streamlit App ---

# Set page config first
st.set_page_config(page_title="Gemini Chatbot DB", layout="wide")

# --- Initialize Database ---
init_db() # Ensure tables exist

# --- Authentication Setup ---
# Fetch user credentials from DB for streamlit-authenticator
try:
    conn = get_db_connection()
    users_db = conn.execute("SELECT username, hashed_password FROM users").fetchall()
    conn.close()
except Exception as e:
    st.error(f"Database connection error during user fetch: {e}")
    users_db = [] # Ensure users_db is iterable even on error

credentials = {
    "usernames": {
        user["username"]: {
            "name": user["username"],
            "password": user["hashed_password"] # Pass the HASH - ensure compatibility!
        } for user in users_db
    }
}

# Get authenticator secret key from st.secrets or environment variable
auth_key = os.environ.get("AUTHENTICATOR_KEY")
if not auth_key:
     try:
          auth_key = st.secrets.get("AUTHENTICATOR_KEY")
     except Exception:
          print("Warning: AUTHENTICATOR_KEY not found in secrets or environment.")
          pass

if not auth_key:
    st.error("Authenticator Key is not configured. Please set it in secrets or env.")
    st.stop() # Stop if key is missing

authenticator = stauth.Authenticate(
    credentials,
    cookie_name="gemini_chatbot_cookie_v2", # Choose a unique name
    key=auth_key, # Use the secret key
    cookie_expiry_days=30
)

# --- Login / App Display Logic ---
name, authentication_status, username = authenticator.login() # Use default location

if authentication_status is False:
    st.error("Username/password is incorrect")
elif authentication_status is None:
    st.warning("Please enter your username and password below.")
    # --- Optional: Add Registration Section Here (or link to it) ---
    with st.expander("Register New User"):
        try:
            new_username = st.text_input("New Username", key="reg_user")
            new_password = st.text_input("New Password", type="password", key="reg_pw")
            new_email = st.text_input("Email (Optional)", key="reg_email")
            if st.button("Register"):
                if not new_username or not new_password:
                    st.error("Username and password are required for registration.")
                else:
                    if add_user(new_username, new_password, new_email):
                        st.success("User registered successfully! Please login.")
                        # Optionally clear fields or use st.experimental_rerun()
                    else:
                        st.error("Registration failed. Username might already exist or DB error occurred.")
        except Exception as e:
             st.error(f"Registration error: {e}")


elif authentication_status is True:
    # --- User is Logged In ---
    st.sidebar.success(f"Welcome *{name}*")
    authenticator.logout("Logout", "sidebar") # Add logout button

    # Get User ID for DB operations
    logged_in_user = get_user(username)
    if not logged_in_user:
         st.error("Critical: Could not find user details after login.")
         st.stop()
    user_id = logged_in_user["id"]

    # --- Main Chat Interface ---
    st.title("Chatbot ✨ (Gemini Powered)")
    # Using query params for location/time as per previous request
    loc_param = st.query_params.get('loc', 'Suva, Fiji')
    time_param = st.query_params.get('time', 'N/A')
    st.caption(f"Chatting as {username} | Location: {loc_param} | Time: {time_param}")

    # Load chat history from DB if not in session or user changed
    if "messages" not in st.session_state or st.session_state.get("current_user_id") != user_id:
        st.session_state.messages = load_user_messages(user_id)
        st.session_state.current_user_id = user_id
        if not st.session_state.messages: # If user has no history yet
             st.session_state.messages = [
                 {"role": "assistant", "content": f"Welcome, {name}! Ask me anything."}
             ]
        st.rerun() # Rerun to display loaded messages immediately


    # Display chat messages from session state
    for message in st.session_state.messages:
        with st.chat_message(message["role"]):
            st.markdown(message["content"])

    # Accept user input
    if prompt := st.chat_input(f"Your message, {name}..."):
        # Add user message to session state immediately
        st.session_state.messages.append({"role": "user", "content": prompt})
        # Display user message
        with st.chat_message("user"):
            st.markdown(prompt)

        # Save user message to DB
        save_message(user_id, "user", prompt)

        # Check for custom response / call API
        custom_answer = get_custom_response(prompt)
        final_bot_response = None

        if custom_answer:
            final_bot_response = custom_answer
            with st.chat_message("assistant"):
                st.markdown(final_bot_response)
        else:
            with st.chat_message("assistant"):
                with st.spinner("Thinking..."):
                    api_history = [
                        {"role": msg["role"], "content": msg["content"]}
                        for msg in st.session_state.messages[:-1] # History before the prompt
                    ]
                    final_bot_response = call_external_api(prompt, api_history)
                    st.markdown(final_bot_response)

        # Add bot response to session state and save to DB
        if final_bot_response is not None:
            st.session_state.messages.append({"role": "assistant", "content": final_bot_response})
            save_message(user_id, "assistant", final_bot_response)
        else:
            print("Warning: bot_response was None, not saving.")