import secrets
# Generates a secure 32-byte random key, represented as 64 hexadecimal characters
secret_key = secrets.token_hex(32)
print(secret_key)