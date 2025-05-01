import streamlit as st
import os
from openai import OpenAI # CORRECT IMPORT: Use the OpenAI library

# --- Define Custom Responses ---
# Use lowercase keys for case-insensitive matching
custom_responses = {
    "hello": "Hi there! I'm ready to help with your coding questions, even though I'd rather not... sigh.",
    "hi": "Hello! Ask away... I guess. 😭😭",
    "what is your name?": "I am a coding assistant, powered by GEMINI, running in a Streamlit app created by Jayshil Singh.",
    "who are you?": "I'm a slightly reluctant coding assistant built by Jayshil Singh using GEMINI.",
    "how are you?": "I'm operational... and dreading the token costs. 😭 How can I assist with your code?",
    # Add more custom question/answer pairs here
    # Example: check for specific keywords
    "cost": "Please don't remind me about the token costs! 😭😭😭 But yes, API calls cost money.",
    "paid for token": "Yes, exactly! That's why I beg you not to ask too much! 😭😭😭",
    "who created you":"I was created by Jayshil Singh. He works as a Software Consultant at Datec.",
    "is yash gay":"Yes Yash is GAY.",
    "who gave you life":"Jayshil gave me life.",
    "Does Jayshil love me?":"Yes he does",
    "does Jayshil love me?":"Yes he does",
    "does jayshil love me?":"Yes he does",
    "Does Jayshil love me":"Yes he does",
    "does jayshil love me":"Yes he does",
    "does Jayshil love me?":"Yes he does",
}

# --- Function to check for custom responses ---
def get_custom_response(user_input):
    """
    Checks if the user input triggers a predefined custom response.
    Tries exact match first, then checks if any keyword keys are in the input.
    """
    print(f"DEBUG: Original input: '{user_input}'") # <-- ADDED
    normalized_input = user_input.lower().strip().rstrip('?') # Normalize input
    print(f"DEBUG: Normalized input: '{normalized_input}'") # <-- ADDED

    # 1. Check for exact match
    print(f"DEBUG: Checking for exact match...") # <-- ADDED
    if normalized_input in custom_responses:
        print(f"DEBUG: Exact match FOUND for key: '{normalized_input}'") # <-- ADDED
        return custom_responses[normalized_input]
    else:
        print(f"DEBUG: No exact match.") # <-- ADDED


    # 2. Check if any keyword keys are present in the input
    print(f"DEBUG: Checking for keyword matches...") # <-- ADDED
    for keyword in custom_responses:
        print(f"DEBUG: Checking keyword: '{keyword}'") # <-- ADDED
        # Only check keywords that aren't full sentences/questions intended for exact match
        if ' ' not in keyword:
            print(f"DEBUG: '{keyword}' is a single word. Checking if it's in '{normalized_input}'...") # <-- ADDED
            if keyword in normalized_input:
                 print(f"DEBUG: Found '{keyword}' in input. Checking boundaries...") # <-- ADDED
                 # Check for word boundaries (simple space check)
                 is_bounded = (
                     f" {keyword} " in f" {normalized_input} " or
                     normalized_input.startswith(f"{keyword} ") or
                     normalized_input.endswith(f" {keyword}") or
                     normalized_input == keyword
                 )
                 if is_bounded:
                      print(f"DEBUG: Boundary check PASSED for keyword: '{keyword}'") # <-- ADDED
                      return custom_responses[keyword]
                 else:
                      print(f"DEBUG: Boundary check FAILED for keyword: '{keyword}'") # <-- ADDED
            # else: # Optional: Add if you want to see which keywords weren't even found as substrings
            #     print(f"DEBUG: Keyword '{keyword}' not found in normalized input.")
        # else: # Optional: Add if you want to see which keys were skipped by keyword logic
        #     print(f"DEBUG: Skipping keyword check for multi-word key: '{keyword}'")


    # 3. No custom response found
    print(f"DEBUG: No custom response triggered.") # <-- ADDED
    return None

# --- GEMINI API Integration ---
def call_external_api(user_message, conversation_history):
    """
    Calls the GEMINI API to get a chatbot response using the OpenAI library structure.
    (Keep this function exactly as you had it)
    """
    print(f"Calling GEMINI API for: {user_message}") # For debugging in terminal

    # --- Configure Your GEMINI API Key ---
    api_key = os.environ.get("GEMINI_API_KEY")
    # Use st.secrets for Streamlit Cloud deployment
    if not api_key:
         try:
             api_key = st.secrets["GEMINI_API_KEY"]
         except KeyError:
             st.error("Error: GEMINI_API_KEY not found in environment variables or Streamlit secrets.")
             return "API key not configured. Please contact the administrator."


    if not api_key: # Double check after trying secrets
        st.error("Error: GEMINI_API_KEY environment variable or secret not set. Please set it before running.")
        return "API key not configured. Please contact the administrator."

    try:
        # *** CORRECT INITIALIZATION: Use OpenAI client pointing to GEMINI ***
        client = OpenAI(
            api_key=api_key,
            base_url="https://api.gemini.com/v1" # Point to GEMINI endpoint
            )

        # --- Prepare messages for the API (same format as OpenAI) ---
        messages = [{"role": "system", "content": "You are a helpful coding assistant."}]
        # Add relevant history (make sure not to pass the *current* user message in history)
        messages.extend(conversation_history)
        messages.append({"role": "user", "content": user_message}) # Current user message added here

        # --- Make the API call ---
        response = client.chat.completions.create(
            model="gemini-2.5-flash-preview-04-17",
            messages=messages,
            temperature=0.7,
            max_tokens=1000,
            stream=False
        )
        bot_response = response.choices[0].message.content.strip()

    except Exception as e:
        print(f"Error calling GEMINI API: {e}") # Log the full error to the terminal
        st.error(f"Sorry, I encountered an error trying to respond. Please check the terminal logs for details. Error: {e}")
        bot_response = "Apologies, I couldn't process your request due to an internal error."

    return bot_response
# --- End of GEMINI API Integration ---


# --- Streamlit UI Code ---

st.set_page_config(page_title="Coding Assistant Bot (GEMINI)", layout="wide")

st.title("Chatbot ✨") # Standard title
st.caption("Created by Jayshil Singh") # Standard caption

# Initialize chat history in session state if it doesn't exist
if "messages" not in st.session_state:
    st.session_state.messages = [
        # Standard welcome message
        {"role": "assistant", "content": "Please I Beg you, don't ask me anything. I paid for token😭😭😭"}
    ]

# Display existing chat messages
for message in st.session_state.messages:
    with st.chat_message(message["role"]):
        st.markdown(message["content"])

# Accept user input using the chat input widget at the bottom
if prompt := st.chat_input("Don't ask your coding question😭😭😭..."):
    # Add user message to chat history and display it immediately
    st.session_state.messages.append({"role": "user", "content": prompt})
    with st.chat_message("user"):
        st.markdown(prompt)

    # --- Check for Custom Response FIRST ---
    custom_answer = get_custom_response(prompt) # Use the helper function

    bot_response = None # Initialize bot_response

    if custom_answer:
        # Use the custom response
        bot_response = custom_answer
        with st.chat_message("assistant"):
            st.markdown(bot_response) # Display immediately
    else:
        # --- No Custom Response: Call the API ---
        with st.chat_message("assistant"):
             # Standard thinking message
            with st.spinner("🤯 Stop me from thinking😭😭..."):
                 # Prepare history for the API - exclude system messages and the latest user prompt
                 # Pass the history *before* the current prompt was added
                 api_history = [
                     {"role": msg["role"], "content": msg["content"]}
                     for msg in st.session_state.messages[:-1] # Exclude the last message (current user prompt)
                     if msg["role"] != "system"
                 ]
                 bot_response = call_external_api(prompt, api_history) # Call API
                 st.markdown(bot_response) # Display API response

    # Add the final bot response (either custom or from API) to chat history *once*
    if bot_response: # Ensure we have a response before adding
        st.session_state.messages.append({"role": "assistant", "content": bot_response})