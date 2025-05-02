# minimal_test.py
import streamlit as st
import time

st.set_page_config(page_title="Session Test")
st.title("Session State Test")

# Initialize counter and timestamp
if 'count' not in st.session_state:
    st.session_state['count'] = 0
    print("DEBUG MINIMAL: Initializing count to 0")
if 'first_load_time' not in st.session_state:
     st.session_state['first_load_time'] = time.time()
     print(f"DEBUG MINIMAL: Initializing first_load_time to {st.session_state['first_load_time']}")

# Increment counter on every run
st.session_state['count'] += 1
current_time = time.time()

# Display values
st.write(f"Rerun Count: {st.session_state['count']}")
st.write(f"Time on First Load: {st.session_state['first_load_time']}")
st.write(f"Current Time: {current_time}")

# Button to trigger a standard rerun
st.button("Trigger Rerun")

# Print to terminal for confirmation
print(f"DEBUG MINIMAL: Run Count is now: {st.session_state['count']}")
print(f"DEBUG MINIMAL: First Load Time in session is: {st.session_state['first_load_time']}")
print("-" * 20) # Separator