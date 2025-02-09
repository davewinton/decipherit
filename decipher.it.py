import base64
import hashlib
from tabulate import tabulate
from Crypto.Cipher import AES


# === Key Derivation (PBKDF2-SHA1) ===
def derive_hmac_key(password, salt, iterations=1000, dklen=32):
    """Derive an HMAC key using PBKDF2-SHA1."""
    return hashlib.pbkdf2_hmac('sha1', password.encode(), salt, iterations, dklen)


# === AES Decryption (AES-256-CTR) ===
def aes_ctr_decrypt(ciphertext, key, nonce):
    """Decrypt the ciphertext using AES-CTR mode with the given key and nonce."""
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    return cipher.decrypt(ciphertext)


# === AES Key Derivation (From Derived Key) ===
def derive_aes_key(derived_key):
    """
    Derives an AES key from the derived key (hexstring) by converting it to Unicode 
    values and encrypting using AES-ECB mode. 
    The final 32-byte AES key is generated using the first 16 bytes of the encryption result.
    """
    unicode_values = [ord(c) for c in derived_key.hex()]  # Convert hexstring to Unicode values
    return aes_ecb_encrypt(bytes(unicode_values[:32]))


# === AES Encryption (AES-256-ECB) ===
def aes_ecb_encrypt(key: bytes) -> bytes:
    """Encrypt the provided key using AES in ECB mode and derive a 32-byte AES key."""
    cipher = AES.new(key, AES.MODE_ECB)
    encrypted_key = cipher.encrypt(key)
    return bytes(encrypted_key[:16] + encrypted_key[:16])  # Duplicate the first 16 bytes

def test_value(val, test_val):
    if val == test_val:
        return "PASSED"
    else:
        return "FAILED"

def test_all_values(data: dict , test_data: dict):
    print(f"Salt:        {test_value(data['Salt']      ,test_data['Salt'])}")
    print(f"Nonce:       {test_value(data['Nonce']     ,test_data['Nonce'])}")
    print(f"DerivedKey:  {test_value(data['DerivedKey'],test_data['DerivedKey'])}")
    print(f"AESKey:      {test_value(data['AESKey']    ,test_data['AESKey'])}")
    print(f"PlainText:   {test_value(data['PlainText'] ,test_data['PlainText'])}")

# === Main Decipher Logic ===
def decipher(enciphered_data, password, test_data=None):
    """Decrypt the encrypted data using the given password."""
    PREFIX = "EnCt2"
    SUFFIX = "IwEmS"

    if not enciphered_data.startswith(PREFIX) or not enciphered_data.endswith(SUFFIX):
        print("Invalid ciphertext format.")
        return None

    # Strip the prefix and suffix
    encrypted_message = enciphered_data[len(PREFIX):-len(SUFFIX)]
    
    # Extract components from the encrypted message
    print("[*] Gathering decryption parameters..")
    hmac_key_hex = encrypted_message[:40] # NOTE: not used 
    salt = encrypted_message[64:72].encode()
    encrypted_data = base64.b64decode(encrypted_message[72:])
    nonce = encrypted_data[:8]
    ciphertext = encrypted_data[8:]
    
    # Derive keys using password and salt
    print("[*] Deriving keys..")
    derived_key = derive_hmac_key(password, salt)
    aes_key = derive_aes_key(derived_key)

    # Verbose output of encryption parameters
    data = {
        "Salt": encrypted_message[64:72],
        "Nonce": nonce.hex(),
        "DerivedKey": derived_key.hex(),
        "AESKey": aes_key.hex(),
        "HMAC_SHA1": hmac_key_hex,
    }
    table = tabulate([(key, value) for key, value in data.items()], 
                     headers=["Parameter", "Value"], 
                     tablefmt="grid")
    print(table)

    # Decrypt the ciphertext
    try:
        print("[*] Decrypting data.. ")
        p_text = aes_ctr_decrypt(ciphertext, aes_key, nonce)

        if test_data:
            # add p_text to data
            data['PlainText'] = p_text.decode()
            # Print header
            print(f"\n=== Testing ===")
            print(f"[*] Password: {test_data['Password']}")
            print(f"[*] CipherText: {test_data['CipherText']}")
            print(f"[*] Matching with known values.. ")
            test_all_values(data,test_data)

        return p_text.decode() 
    except UnicodeDecodeError as e:
        print(f"[!] Error: {e}")
        return None


# === Testing Function ===
def test():
    """ Test decryption against known data """
    enciphered = "EnCt2bbd78913842cb78ca77c4bcf85e8df078858cb77bbd78913842cb78ca77c4bcfrnzIvb9CBgCfrLT/p2f5l+wqR6Q4DhSRCg==IwEmS"
    passwd = "password"
    data = {
        "Password":"password",
        "Salt": "rnzIvb9C",
        "Nonce": "06009facb4ffa767",
        "DerivedKey": "77b8f02a2a2a003b27954ca85611639de35e43f560ec2514391bd2228ace66c3",
        "HMAC_SHA1": None,
        "AESKey": "3eaaf3c83750a3d0082294a5ba8b12573eaaf3c83750a3d0082294a5ba8b1257",
        "CipherText": "BgCfrLT/p2f5l+wqR6Q4DhSRCg==",
        "PlainText":"Hello World"
    }

    # Perform decryption
    deciphered = decipher(enciphered, passwd, test_data=data)

    # Validate the result
    if deciphered == data['PlainText']:
        print("[+] Decryption successful!\n\n")
        print(f"=== Decrypted Message ===\n{deciphered}")
    else:
        print("[X] Decryption failed!")


# === Main Entry Point ===
def main():
    """Main function to run the decryption."""
    # NOTE: Put your ciphertext in 'enciphered' and the decryption password in 'passwd'
    # ciphertext should contain the "EnCt2" prefix and the "IwEmS" suffix
    enciphered = ""
    passwd = ""
    deciphered = decipher(enciphered, passwd)

    if deciphered:
        print("[+] Decryption successful!\n\n")
        print(f"=== Decrypted Message ===\n{deciphered}")
    else:
        print("[X] Decryption failed!")


if __name__ == "__main__":
    # Uncomment to run tests
    # test()
    main()
