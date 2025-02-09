# decipherit.py
A Python-based decryption tool for ciphertexts generated by the now-defunct Encipher.it web encryption service.

## Overview
Encipher.it was a web-based encryption service that is no longer available, now redirecting to an unrelated crypto-casino website. This tool enables decryption of ciphertexts created by Encipher.it, ensuring users can still access their encrypted data. The tool is functional but minimalistic, it's primary use is to decrypt the data so it can still be accessed with no extra bells or whistles.

The encipher.it crypto system was non-standard in many ways, and did some strange things for KDF and encoding/decoding. It took quite a bit of reverse engineering the javascript to get everything up and running. For completeness sake I have included some overly verbose comments which document some of the weird quirks which need to be satisfied for decryption to work, if any devs out there would find them interesting/useful. 

## Requirements

Install dependencies with:
`pip install pycryptodome tabulate`

## Usage

Add your `ciphertext` and `password` at the bottom of the script.

Run the script:

`python3 decipher.it.py`

## Verbose Output

The tool prints decryption parameters for reference. To disable this, remove or comment out:

`print(table)`

## Testing

A `test()` function verifies decryption against known values (salt, ciphertext, plaintext etc.). 

To run tests, uncomment `test()` and comment out `main()` at the bottom of the script.

### Example Output

```shell
python3 decipher.it.py
[*] Gathering decryption parameters..
[*] Deriving keys..
+-------------+------------------------------------------------------------------+
| Parameter   | Value                                                            |
+=============+==================================================================+
| Salt        | rnzIvb9C                                                         |
+-------------+------------------------------------------------------------------+
| Nonce       | 06009facb4ffa767                                                 |
+-------------+------------------------------------------------------------------+
| DerivedKey  | 77b8f02a2a2a003b27954ca85611639de35e43f560ec2514391bd2228ace66c3 |
+-------------+------------------------------------------------------------------+
| AESKey      | 3eaaf3c83750a3d0082294a5ba8b12573eaaf3c83750a3d0082294a5ba8b1257 |
+-------------+------------------------------------------------------------------+
| HMAC_SHA1   | bbd78913842cb78ca77c4bcf85e8df078858cb77                         |
+-------------+------------------------------------------------------------------+
[*] Decrypting data..

=== Testing ===
[*] Password: password
[*] CipherText: BgCfrLT/p2f5l+wqR6Q4DhSRCg==
[*] Matching with known values..
Salt:        PASSED
Nonce:       PASSED
DerivedKey:  PASSED
AESKey:      PASSED
PlainText:   PASSED
[+] Decryption successful!


=== Decrypted Message ===
Hello World
```
