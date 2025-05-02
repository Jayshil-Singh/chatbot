# --- Imports ---
import streamlit as st
import os
import google.generativeai as genai
import sqlite3
from datetime import datetime
from typing import List, Dict, Union, Optional, Any
import json
import secrets
from authlib.integrations.requests_client import OAuth2Session
import time # For session state example

# --- Constants & Config ---
DATABASE_NAME = 'chatbot_data_google_auth.db'

# --- Load Secrets (Ensure these are set!) ---
try:
    GOOGLE_CLIENT_ID = st.secrets["GOOGLE_CLIENT_ID"]
    GOOGLE_CLIENT_SECRET = st.secrets["GOOGLE_CLIENT_SECRET"]
    GOOGLE_REDIRECT_URI = st.secrets["GOOGLE_REDIRECT_URI"] # Must match GCP config exactly
    APP_SECRET_KEY = st.secrets["APP_SECRET_KEY"] # Used for state validation (CSRF)
    GEMINI_API_KEY = st.secrets["GEMINI_API_KEY"]
except KeyError as e:
    st.error(f"ERROR: Missing secret: {e}. Configure in .streamlit/secrets.toml or Cloud Settings.")
    st.stop()
except Exception as e:
     st.error(f"Error loading secrets: {e}")
     st.stop()

# Google OAuth Endpoints & Scope
AUTHORIZATION_ENDPOINT = 'https://accounts.google.com/o/oauth2/v2/auth'
TOKEN_ENDPOINT = 'https://oauth2.googleapis.com/token'
SCOPE = "openid email profile"

# --- Database Functions ---

def get_db_connection() -> sqlite3.Connection:
    """Establishes a connection to the SQLite database."""
    conn = sqlite3.connect(DATABASE_NAME, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initializes the database and tables if they don't exist."""
    conn = get_db_connection()
    try:
        with conn: # Use context manager for commit/rollback
            conn.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    google_id TEXT UNIQUE NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    name TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            conn.execute('''
                CREATE TABLE IF NOT EXISTS messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    role TEXT NOT NULL CHECK(role IN ('user', 'assistant')),
                    content TEXT NOT NULL,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users (id)
                )
            ''')
        print("Database initialized/checked.")
    except Exception as e:
        print(f"Error initializing database: {e}")
    finally:
        if conn: conn.close()

def get_user_by_google_id(google_id: str) -> Optional[sqlite3.Row]:
    """Retrieves user details by Google ID."""
    conn = get_db_connection()
    user = None
    try:
        user = conn.execute("SELECT * FROM users WHERE google_id = ?", (google_id,)).fetchone()
    except Exception as e: print(f"Error getting user by google_id: {e}")
    finally:
        if conn: conn.close()
    return user

def add_google_user(google_id: str, email: str, name: str) -> Optional[int]:
    """Adds a new user from Google Sign-In details, returns app user ID."""
    conn = get_db_connection()
    user_id = None
    try:
        with conn:
            cursor = conn.execute(
                "INSERT INTO users (google_id, email, name) VALUES (?, ?, ?)",
                (google_id, email, name)
            )
            user_id = cursor.lastrowid
            print(f"User added via Google: email='{email}', app_id={user_id}")
    except sqlite3.IntegrityError:
        print(f"User already exists: google_id='{google_id}' or email='{email}'")
        # If already exists due to unique constraint, fetch existing ID
        existing_user = get_user_by_google_id(google_id)
        user_id = existing_user['id'] if existing_user else None
    except Exception as e:
        print(f"Error adding Google user: {e}")
    finally:
        if conn: conn.close()
    return user_id

def save_message(user_id: int, role: str, content: str):
    """Saves a chat message."""
    conn = get_db_connection()
    try:
        with conn:
            conn.execute(
                "INSERT INTO messages (user_id, role, content) VALUES (?, ?, ?)",
                (user_id, role, content)
            )
    except Exception as e: print(f"Error saving message: {e}")
    finally:
        if conn: conn.close()

def load_user_messages(user_id: int) -> List[Dict[str, str]]:
    """Loads chat messages for a user."""
    conn = get_db_connection()
    messages = []
    try:
        messages_rows = conn.execute(
            "SELECT role, content FROM messages WHERE user_id = ? ORDER BY timestamp ASC",
            (user_id,)
        ).fetchall()
        messages = [{"role": row["role"], "content": row["content"]} for row in messages_rows]
    except Exception as e: print(f"Error loading messages: {e}")
    finally:
        if conn: conn.close()
    return messages

# --- Custom Response Logic ---
custom_responses: Dict[str, str] = {
    "hello": "Hi there! I'm ready to help with your coding questions...",
    "hi": "Hello! Ask away... I guess. 😭😭",
    "what is your name?": "I am a coding assistant, powered by GEMINI...",
    "who are you?": "I'm a slightly reluctant coding assistant built by Jayshil Singh using GEMINI.",
    "how are you?": "I'm operational... and dreading the token costs...",
    "cost": "Please don't remind me about the token costs!...",
    "paid for token": "Yes, exactly! That's why I beg you not to ask too much!...",
    "who created you": "I was created by Jayshil Singh...",
    "is yash gay": "Yes Yash is GAY.",
    "who gave you life": "Jayshil gave me life.",
    "does jayshil love me": "Yes he does",
}

def get_custom_response(user_input: str) -> Optional[str]:
    """Checks if user input triggers a predefined custom response."""
    normalized_input = user_input.lower().strip().rstrip('?')
    if normalized_input in custom_responses: return custom_responses[normalized_input]
    for keyword in custom_responses:
        if ' ' not in keyword and keyword in normalized_input:
            is_bounded = ( f" {keyword} " in f" {normalized_input} " or normalized_input.startswith(f"{keyword} ") or normalized_input.endswith(f" {keyword}") or normalized_input == keyword )
            if is_bounded: return custom_responses[keyword]
    return None

# --- Gemini API Call Logic ---
def call_external_api(user_message: str, conversation_history: List[Dict[str, str]]) -> str:
    """Calls the Google Gemini API."""
    print(f"Attempting to call Gemini API for: {user_message}")
    try:
        genai.configure(api_key=GEMINI_API_KEY)
        model = genai.GenerativeModel('gemini-1.5-flash-latest')
        gemini_history = [{'role': ('user' if msg['role'] == 'user' else 'model'), 'parts': [msg['content']]} for msg in conversation_history]
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

# --- Authlib OAuth Client Setup ---
client = OAuth2Session(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET,
                       scope=SCOPE, redirect_uri=GOOGLE_REDIRECT_URI)

# --- Main Streamlit App ---

st.set_page_config(page_title="Gemini Chatbot (Google Login)", layout="wide")

# Initialize Database on first run
init_db()

# Initialize session state keys
if 'authenticated' not in st.session_state: st.session_state['authenticated'] = False
if 'user_info' not in st.session_state: st.session_state['user_info'] = None # Will store user record dict
if 'app_user_id' not in st.session_state: st.session_state['app_user_id'] = None # App's internal user ID
if 'oauth_state' not in st.session_state: st.session_state['oauth_state'] = None # CSRF protection

# --- Handle OAuth Callback ---
query_params = st.query_params
auth_code = query_params.get("code")
returned_state = query_params.get("state")
stored_state = st.session_state.get('oauth_state')

# Only process if we received a code and we have a state stored (expecting callback)
if auth_code and stored_state:
    print("Processing OAuth callback...")
    if returned_state != stored_state:
        st.error("Invalid state parameter. Authentication failed (CSRF?). Please try logging in again.")
        print(f"STATE MISMATCH: Returned='{returned_state}', Stored='{stored_state}'")
        st.session_state['oauth_state'] = None # Clear invalid state
    else:
        st.session_state['oauth_state'] = None # Clear state after successful use
        print("OAuth State OK. Fetching token...")
        try:
            # Prepare the full callback URL to pass for verification
            full_callback_url = st.get_option("server.baseUrlPath") + "?" + "&".join([f"{k}={v}" for k, v in query_params.items()])
            # Note: Constructing the URL manually might be fragile. Passing only code might work.
            # Check Authlib docs if token fetch fails.

            token = client.fetch_token(
                TOKEN_ENDPOINT,
                # Use the authorization_response parameter to pass the full callback URL
                authorization_response=full_callback_url,
                # Alternatively, pass code directly if URL method fails:
                # code=auth_code,
                # Authlib might require client_secret depending on provider/setup
                # client_secret=GOOGLE_CLIENT_SECRET # Usually needed for web server flow
            )
            print("Token received.")

            # Parse and Verify ID Token
            # Authlib's parse_id_token performs basic checks (signature, expiry)
            userinfo = client.parse_id_token(token)
            print("ID Token parsed.")

            # --- Additional Verification (Issuer & Audience) ---
            if userinfo.get('iss') not in ['https://accounts.google.com', 'accounts.google.com']:
                 raise ValueError(f"Invalid token issuer: {userinfo.get('iss')}")
            if userinfo.get('aud') != GOOGLE_CLIENT_ID:
                 raise ValueError(f"Invalid token audience: {userinfo.get('aud')}")
            print("ID Token iss and aud verified.")

            google_id = userinfo.get('sub')
            email = userinfo.get('email')
            name = userinfo.get('name')

            if not google_id or not email:
                st.error("Could not retrieve Google ID or email from token.")
            else:
                # Get/Add user in our database
                user = get_user_by_google_id(google_id)
                app_user_id_local = None
                user_record_dict = None

                if user: # Existing user
                    app_user_id_local = user['id']
                    user_record_dict = dict(user)
                    print(f"Found existing user: {email} (App ID: {app_user_id_local})")
                else: # New user
                    print(f"Creating new user account for: {email}")
                    app_user_id_local = add_google_user(google_id, email, name)
                    if app_user_id_local:
                         new_user_record = get_user_by_google_id(google_id)
                         user_record_dict = dict(new_user_record) if new_user_record else None
                    else:
                         st.error("Failed to create user account in database.")

                # If user processed successfully
                if app_user_id_local and user_record_dict:
                     print("OAuth callback successful. Setting session state.")
                     st.session_state['authenticated'] = True
                     st.session_state['app_user_id'] = app_user_id_local
                     st.session_state['user_info'] = user_record_dict # Store user DB record

                     # --- Clean URL Query Params (JavaScript Workaround) ---
                     # This attempts to remove the code/state from URL bar without a full page reload
                     st.markdown(
                         """
                         <script>
                             if (window.history.replaceState) {
                                 const url = new URL(window.location.href);
                                 url.searchParams.delete('code');
                                 url.searchParams.delete('state');
                                 url.searchParams.delete('scope');
                                 url.searchParams.delete('authuser');
                                 url.searchParams.delete('prompt');
                                 window.history.replaceState({path: url.pathname}, '', url.pathname);
                             }
                         </script>
                         """, unsafe_allow_html=True)
                     # --- Trigger Rerun ---
                     # Ensures the UI updates immediately to the authenticated state
                     # and that the callback code doesn't run again unintentionally
                     print("Rerunning after successful auth callback.")
                     time.sleep(0.1) # Small delay MAY sometimes help JS execute before rerun
                     st.rerun()
                else:
                     print("Callback failed: Could not get/create user ID or record.")
                     st.error("Authentication failed during user processing.")

        except Exception as e:
            st.error(f"Error during OAuth processing: {e}")
            print(f"OAUTH CALLBACK ERROR: {e}") # Log detailed error

# --- Main UI Rendering Logic ---

if st.session_state.get('authenticated'):
    # --- User is Authenticated ---
    user_info = st.session_state.get('user_info', {})
    app_user_id = st.session_state.get('app_user_id')

    # Safety check for session state
    if not user_info or not app_user_id:
         st.error("Session error. Please login again.")
         st.session_state['authenticated'] = False
         st.session_state['user_info'] = None
         st.session_state['app_user_id'] = None
         st.session_state['oauth_state'] = None
         if st.button("Refresh Login"): st.rerun()
         st.stop()

    # --- Authenticated App UI ---
    st.sidebar.success(f"Welcome *{user_info.get('name', 'User')}*")
    if st.sidebar.button("Logout"):
        # Clear session state
        for key in list(st.session_state.keys()):
            del st.session_state[key]
        # Rerun to show the logged-out state
        st.rerun()

    # Chatbot Interface
    st.title("Chatbot ✨ (Logged in via Google)")
    loc_param = st.query_params.get('loc', 'Suva, Fiji')
    time_param = st.query_params.get('time', 'N/A')
    st.caption(f"Chatting as {user_info.get('email', 'N/A')} | Location: {loc_param} | Time: {time_param}")

    # Initialize/Load chat history
    if "messages" not in st.session_state or st.session_state.get("current_app_user_id") != app_user_id:
        print(f"Loading messages for user_id: {app_user_id}")
        st.session_state.messages = load_user_messages(app_user_id)
        st.session_state.current_app_user_id = app_user_id
        if not st.session_state.messages:
             st.session_state.messages = [{"role": "assistant", "content": f"Welcome, {user_info.get('name', 'User')}! How can I help?"}]
        st.rerun() # Rerun to display loaded messages

    # Display chat messages
    for message in st.session_state.messages:
        with st.chat_message(message["role"]):
            st.markdown(message["content"])

    # Chat input
    if prompt := st.chat_input(f"Your message, {user_info.get('name', 'User')}..."):
        st.session_state.messages.append({"role": "user", "content": prompt})
        with st.chat_message("user"): st.markdown(prompt)
        save_message(app_user_id, "user", prompt)

        # Get bot response (custom or API)
        custom_answer = get_custom_response(prompt)
        final_bot_response = None
        if custom_answer:
            final_bot_response = custom_answer
            with st.chat_message("assistant"): st.markdown(final_bot_response)
        else:
            with st.chat_message("assistant"):
                with st.spinner("Thinking..."):
                    api_history = [{"role": msg["role"], "content": msg["content"]} for msg in st.session_state.messages[:-1]]
                    final_bot_response = call_external_api(prompt, api_history)
                    st.markdown(final_bot_response)

        # Save bot response
        if final_bot_response is not None:
            st.session_state.messages.append({"role": "assistant", "content": final_bot_response})
            save_message(app_user_id, "assistant", final_bot_response)
        else:
            print("Warning: bot_response was None, not saving.")

else:
    # --- User Not Authenticated ---
    st.title("Chatbot Login")
    st.warning("Please login using your Google Account to continue.")

    # Create Login Button/Link
    try:
        csrf_state = secrets.token_urlsafe(16)
        st.session_state['oauth_state'] = csrf_state # Store state before creating URL
        authorization_url, state = client.create_authorization_url(
            AUTHORIZATION_ENDPOINT, state=csrf_state)
        print(f"Generated login link with state: {csrf_state}")
        st.link_button("Login with Google", authorization_url)
    except Exception as e:
        st.error(f"Error creating login button: {e}")
        print(f"Error during OAuth URL generation: {e}")