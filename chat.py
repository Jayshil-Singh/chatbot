# --- Imports ---
import streamlit as st
import os
import google.generativeai as genai
import sqlite3
from datetime import datetime
from typing import List, Dict, Union, Optional, Any
import json # For parsing token response
import secrets # For generating state parameter
from authlib.integrations.requests_client import OAuth2Session # pip install Authlib requests

# --- Constants & Config ---
DATABASE_NAME = 'chatbot_data_google_auth.db' # New DB name for clarity

# Load secrets - **REQUIRED**
try:
    GOOGLE_CLIENT_ID = st.secrets["GOOGLE_CLIENT_ID"]
    GOOGLE_CLIENT_SECRET = st.secrets["GOOGLE_CLIENT_SECRET"]
    # MUST match one of the URIs configured in GCP Credentials
    GOOGLE_REDIRECT_URI = st.secrets["GOOGLE_REDIRECT_URI"]
    # Used for CSRF protection via 'state' parameter
    APP_SECRET_KEY = st.secrets["APP_SECRET_KEY"] # Generate a strong random key yourself
    GEMINI_API_KEY = st.secrets["GEMINI_API_KEY"]
except KeyError as e:
    st.error(f"ERROR: Missing secret configuration: {e}. Please set up .streamlit/secrets.toml")
    st.stop()
except Exception as e:
     st.error(f"Error loading secrets: {e}")
     st.stop()

# Google OAuth 2.0 Endpoints (fetch dynamically or hardcode)
# Using hardcoded common endpoints for simplicity here
AUTHORIZATION_ENDPOINT = 'https://accounts.google.com/o/oauth2/v2/auth'
TOKEN_ENDPOINT = 'https://oauth2.googleapis.com/token'
USERINFO_ENDPOINT = 'https://openidconnect.googleapis.com/v1/userinfo' # Or parse id_token
# Required scopes for profile info
SCOPE = "openid email profile"


# --- Database Functions (Modified for Google Auth) ---

def get_db_connection() -> sqlite3.Connection:
    """Establishes a connection to the SQLite database."""
    # check_same_thread=False is needed for Streamlit's multithreading
    conn = sqlite3.connect(DATABASE_NAME, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initializes the database for Google OAuth users."""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                google_id TEXT UNIQUE NOT NULL, -- Google's unique subject ID ('sub')
                email TEXT UNIQUE NOT NULL,
                name TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL, -- This app's user ID
                role TEXT NOT NULL CHECK(role IN ('user', 'assistant')),
                content TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        conn.commit()
        print("Database initialized for Google OAuth.")
    except Exception as e:
        print(f"Error initializing database: {e}")
    finally:
        if conn:
            conn.close()

def get_user_by_google_id(google_id: str) -> Optional[sqlite3.Row]:
    """Retrieves user details by their unique Google ID ('sub')."""
    conn = get_db_connection()
    user = None
    try:
        user = conn.execute("SELECT * FROM users WHERE google_id = ?", (google_id,)).fetchone()
    except Exception as e:
        print(f"Error getting user by google_id: {e}")
    finally:
        if conn:
            conn.close()
    return user

def add_google_user(google_id: str, email: str, name: str) -> Optional[int]:
    """Adds a new user from Google Sign-In details and returns their app user ID."""
    conn = get_db_connection()
    user_id = None
    try:
        cursor = conn.execute(
            "INSERT INTO users (google_id, email, name) VALUES (?, ?, ?)",
            (google_id, email, name)
        )
        conn.commit()
        user_id = cursor.lastrowid
        print(f"User added via Google: email='{email}', app_id={user_id}")
    except sqlite3.IntegrityError:
        print(f"User already exists (IntegrityError): google_id='{google_id}' or email='{email}'")
        conn.rollback()
        existing_user = get_user_by_google_id(google_id) # Fetch existing user ID
        user_id = existing_user['id'] if existing_user else None
    except Exception as e:
        print(f"Error adding Google user: {e}")
        conn.rollback()
    finally:
        if conn:
            conn.close()
    return user_id

# --- Message DB Functions (Keep as before) ---
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
        if conn:
            conn.close()

def load_user_messages(user_id: int) -> List[Dict[str, str]]:
    """Loads all messages for a specific user, ordered by timestamp."""
    conn = get_db_connection()
    messages = []
    try:
        messages_rows = conn.execute(
            "SELECT role, content FROM messages WHERE user_id = ? ORDER BY timestamp ASC",
            (user_id,)
        ).fetchall()
        messages = [{"role": row["role"], "content": row["content"]} for row in messages_rows]
    except Exception as e:
        print(f"Error loading messages: {e}")
    finally:
        if conn:
            conn.close()
    return messages


# --- Custom Response Logic (Keep as before) ---
# (custom_responses dictionary and get_custom_response function)
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
    if normalized_input in custom_responses: return custom_responses[normalized_input]
    for keyword in custom_responses:
        if ' ' not in keyword and keyword in normalized_input:
            is_bounded = ( f" {keyword} " in f" {normalized_input} " or normalized_input.startswith(f"{keyword} ") or normalized_input.endswith(f" {keyword}") or normalized_input == keyword )
            if is_bounded: return custom_responses[keyword]
    return None

# --- Gemini API Call Logic (Keep as before) ---
# (call_external_api function)
def call_external_api(user_message: str, conversation_history: List[Dict[str, str]]) -> str:
    """Calls the Google Gemini API to get a chatbot response."""
    print(f"Attempting to call Gemini API for: {user_message}")
    try:
        genai.configure(api_key=GEMINI_API_KEY) # Use loaded secret
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
# Note: state is generated per request later
client = OAuth2Session(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET,
                       scope=SCOPE, redirect_uri=GOOGLE_REDIRECT_URI)

# --- Main Streamlit App ---

# Set page config first
st.set_page_config(page_title="Gemini Chatbot (Google Login)", layout="wide")

# Initialize Database
init_db()

# Initialize session state variables
if 'authenticated' not in st.session_state: st.session_state['authenticated'] = False
if 'user_info' not in st.session_state: st.session_state['user_info'] = None
if 'app_user_id' not in st.session_state: st.session_state['app_user_id'] = None
if 'oauth_state' not in st.session_state: st.session_state['oauth_state'] = None # For CSRF protection

# --- Handle OAuth Callback ---
# Check query parameters when the script reruns after Google redirect
query_params = st.query_params # Use the modern way

auth_code = query_params.get("code")
returned_state = query_params.get("state")

# Only process callback if code exists and we were expecting a callback (state exists in session)
if auth_code and st.session_state.get('oauth_state'):
    print("DEBUG: OAuth callback detected.")
    # Verify CSRF state token
    if returned_state != st.session_state['oauth_state']:
        st.error("Invalid state parameter. Authentication failed (CSRF detected).")
        st.session_state['oauth_state'] = None # Clear invalid state
    else:
        st.session_state['oauth_state'] = None # Clear state after use
        try:
            # Fetch token from Google
            token = client.fetch_token(
                TOKEN_ENDPOINT,
                authorization_response=f"{GOOGLE_REDIRECT_URI}?code={auth_code}&state={returned_state}", # Pass full redirect URL
                # Authlib usually infers code from the auth response URL
                # client_secret=GOOGLE_CLIENT_SECRET # Often needed, depends on client setup
            )

            # Parse and verify ID token (CRITICAL STEP)
            # Use Authlib's built-in parsing which includes basic validation
            # For production, add stricter checks (nonce if used, etc.)
            userinfo = client.parse_id_token(token)

            # --- Additional Verification (Issuer & Audience) ---
            if userinfo.get('iss') not in ['https://accounts.google.com', 'accounts.google.com']:
                 raise ValueError("Invalid token issuer.")
            if userinfo.get('aud') != GOOGLE_CLIENT_ID:
                 raise ValueError("Invalid token audience.")
            # Expiry is usually checked by parse_id_token

            google_id = userinfo.get('sub')
            email = userinfo.get('email')
            name = userinfo.get('name')

            if not google_id or not email:
                st.error("Could not retrieve Google ID or email from token.")
            else:
                # User is verified, get/create user in our database
                user = get_user_by_google_id(google_id)
                app_user_id_local = None
                if user:
                    app_user_id_local = user['id']
                    print(f"Existing user logged in via Google: {email} (App ID: {app_user_id_local})")
                    st.session_state['user_info'] = dict(user) # Store full user record
                else:
                    print(f"New user via Google: {email}. Creating account...")
                    app_user_id_local = add_google_user(google_id, email, name)
                    if app_user_id_local:
                         # Fetch the newly created record to store
                         new_user_record = get_user_by_google_id(google_id)
                         st.session_state['user_info'] = dict(new_user_record) if new_user_record else None
                    else:
                         st.error("Failed to create user account in database.")
                         # Don't set authenticated if user creation failed

                # If we successfully got/created the user and got an app_user_id
                if app_user_id_local:
                     st.session_state['authenticated'] = True
                     st.session_state['app_user_id'] = app_user_id_local
                     # Use JavaScript via markdown to clear query params after processing
                     # This prevents reprocessing on refresh. It's a workaround.
                     st.markdown(
                         """
                         <script>
                             // Attempt to remove query parameters from URL without reload
                             if (window.history.replaceState) {
                                 const url = new URL(window.location.href);
                                 url.searchParams.delete('code');
                                 url.searchParams.delete('state');
                                 url.searchParams.delete('scope'); // Google often adds scope back too
                                 url.searchParams.delete('authuser');
                                 url.searchParams.delete('prompt');
                                 window.history.replaceState({path: url.pathname}, '', url.pathname);
                             }
                         </script>
                         """, unsafe_allow_html=True)
                     # Trigger immediate rerun to reflect login state without query params
                     print("DEBUG: Rerunning after successful auth callback.")
                     st.rerun()


        except Exception as e:
            st.error(f"Error during OAuth token fetch or validation: {e}")
            print(f"OAuth Error Details: {e}") # Log detailed error

# --- Main UI Rendering ---

if st.session_state.get('authenticated'):
    # --- User is Authenticated ---
    user_info = st.session_state.get('user_info', {})
    app_user_id = st.session_state.get('app_user_id')

    if not user_info or not app_user_id:
         # Should ideally not happen if state management is correct
         st.error("Session error. Please login again.")
         st.session_state['authenticated'] = False
         st.session_state['user_info'] = None
         st.session_state['app_user_id'] = None
         st.session_state['oauth_state'] = None
         if st.button("Refresh Login"): st.rerun()
         st.stop()

    st.sidebar.success(f"Welcome *{user_info.get('name', 'User')}*")
    if st.sidebar.button("Logout"):
        # Clear session state on logout
        st.session_state['authenticated'] = False
        st.session_state['user_info'] = None
        st.session_state['app_user_id'] = None
        st.session_state['oauth_state'] = None
        # Clear chat history maybe? Or just let it reload on next login
        if 'messages' in st.session_state: del st.session_state['messages']
        if 'current_app_user_id' in st.session_state: del st.session_state['current_app_user_id']
        # Rerun to show the logged-out state
        st.rerun()

    # --- Chatbot Interface ---
    st.title("Chatbot ✨ (Logged in via Google)")
    loc_param = st.query_params.get('loc', 'Suva, Fiji')
    time_param = st.query_params.get('time', 'N/A')
    st.caption(f"Chatting as {user_info.get('email', 'N/A')} | Location: {loc_param} | Time: {time_param}")

    # Load/Initialize chat history for the logged-in user
    if "messages" not in st.session_state or st.session_state.get("current_app_user_id") != app_user_id:
        st.session_state.messages = load_user_messages(app_user_id)
        st.session_state.current_app_user_id = app_user_id
        if not st.session_state.messages:
             st.session_state.messages = [{"role": "assistant", "content": f"Welcome, {user_info.get('name', 'User')}! How can I help?"}]
        st.rerun() # Display loaded history

    # Display chat messages
    for message in st.session_state.messages:
        with st.chat_message(message["role"]):
            st.markdown(message["content"])

    # Accept user input
    if prompt := st.chat_input(f"Your message, {user_info.get('name', 'User')}..."):
        st.session_state.messages.append({"role": "user", "content": prompt})
        with st.chat_message("user"): st.markdown(prompt)
        save_message(app_user_id, "user", prompt)

        # Process message (custom response or API)
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

        # Save and display bot response
        if final_bot_response is not None:
            st.session_state.messages.append({"role": "assistant", "content": final_bot_response})
            save_message(app_user_id, "assistant", final_bot_response)
        else:
            print("Warning: bot_response was None, not saving.")

else:
    # --- User Not Authenticated ---
    st.warning("Please login using your Google Account.")

    # Create Login Button
    try:
        # Generate CSRF state token
        csrf_state = secrets.token_urlsafe(16)
        # Store state in session *before* creating URL
        st.session_state['oauth_state'] = csrf_state

        # Create authorization URL
        authorization_url, state = client.create_authorization_url(
            AUTHORIZATION_ENDPOINT, state=csrf_state)

        print(f"DEBUG: Generated auth URL: {authorization_url}") # Log for debugging redirect issues

        # Create a link (less intrusive than auto-redirect)
        st.link_button("Login with Google", authorization_url)

        # --- Alternative: Auto-redirect (use with caution) ---
        # Use st.markdown to inject JavaScript for redirection
        # st.markdown(f'<a href="{authorization_url}" target="_self">Login with Google</a>', unsafe_allow_html=True)
        # Or auto-redirect (can be jarring):
        # if st.button("Login with Google", key="login_btn"): # Button can trigger the JS injection
        #      st.markdown(f"""
        #          <script>
        #              window.location.href = "{authorization_url}";
        #          </script>
        #      """, unsafe_allow_html=True)
        #      st.stop() # Stop script execution after initiating redirect

    except Exception as e:
        st.error(f"Error creating login button: {e}")
        print(f"Error during OAuth URL generation: {e}")