from Crypto.Cipher import AES

def aes_ctr_decrypt(ciphertext, key, nonce):
    """Decrypt the ciphertext using AES-CTR mode with the given key and nonce."""
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    return cipher.decrypt(ciphertext)

# Hexstrings containing decryption params
aes_key = "3eaaf3c83750a3d0082294a5ba8b12573eaaf3c83750a3d0082294a5ba8b1257"
nonce = "06009facb4ffa767"
ciphertext = "f997ec2a47a4380e14910a"

# Replace param with nonce, aes_key or ciphertext and hex_value with the matching hexstring
key = bytes.fromhex(aes_key)
nonce = bytes.fromhex(nonce)
ctext = bytes.fromhex(ciphertext)

# AES-CTR Decryption
print(f"Deciphered: {aes_ctr_decrypt(ctext, key, nonce).decode()}")