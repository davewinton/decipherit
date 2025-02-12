from Crypto.Cipher import AES
from getpass import getpass
from os import urandom
import hashlib, hmac

# === Key Derivation (PBKDF2-SHA1) ===
def derive_hmac_key(password, salt, iterations=1000, dklen=32):
    """Derive an HMAC key using PBKDF2-SHA1."""
    return hashlib.pbkdf2_hmac('sha512', password.encode(), salt, iterations, dklen)

# === Calculate HMAC (HMAC_SHA512) ===
def calc_hmac(key, data):
    return hmac.new(key, data, hashlib.sha512).digest()

# === AES Encryption (AES-256-CTR) ===
def aes_ctr_encrypt(plaintext, key):
    """Decrypt the ciphertext using AES-CTR mode with the given key and nonce."""
    nonce = urandom(8) # Get 8 random bytes
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    return nonce + cipher.encrypt(plaintext)

# === AES Decryption (AES-256-CTR) ===
def aes_ctr_decrypt(ciphertext, key):
    """Decrypt the ciphertext using AES-CTR mode with the given key and nonce."""
    nonce = ciphertext[:8]
    ciphertext = ciphertext[8:]
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    return cipher.decrypt(ciphertext)

msg = "Hello World"
passwd = getpass("Enter Encryption Password: ")
salt = urandom(16) # Get 16 random bytes

# Derive encryption key
derived_key = derive_hmac_key(passwd, 
                              salt, 
                              iterations=1000000, 
                              dklen=32)

# Calculate HMAC_SHA512
hmac_s512 = calc_hmac(derived_key, msg.encode())

# Encrypt msg with derived_key
ciphertext = hmac_s512 + salt + aes_ctr_encrypt(msg.encode(), derived_key)
print(f"Ciphertext: {ciphertext.hex()}")

# Extract decryption params
passwd = getpass("Enter Decryption Password: ")
hmac_s512_hex = ciphertext[:64]
salt = ciphertext[64:80]
dervied_key = derive_hmac_key(passwd, 
                              salt, 
                              iterations=1000000, 
                              dklen=32)
ciphertext = ciphertext[80:]

# Decrypt the ciphertext and verify the HMAC_SHA512
plaintext = aes_ctr_decrypt(ciphertext, derived_key)
if calc_hmac(derived_key, plaintext) == hmac_s512_hex:
    print("[+] HMAC Verified")
    print(f"Plaintext: {plaintext.decode()}")
else:
    print("[X] HMAC Failed!")
