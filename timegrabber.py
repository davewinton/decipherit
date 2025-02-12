import datetime

nonce= "06009facb4ffa767"
# Convert hex string to byte array
counterBlock = bytes.fromhex(nonce)

# Step 1: Reconstruct nonceMs (milliseconds)
nonceMs = (counterBlock[1] << 8) | counterBlock[0]

# Step 2: Reconstruct nonceRnd (random value)
nonceRnd = (counterBlock[3] << 8) | counterBlock[2]

# Step 3: Reconstruct nonceSec (seconds)
nonceSec = (counterBlock[7] << 24) | (counterBlock[6] << 16) | (counterBlock[5] << 8) | counterBlock[4]

# Step 4: Combine nonceSec and nonceMs to get the full timestamp (in milliseconds)
original_timestamp = nonceSec * 1000 + nonceMs

# Convert to human-readable UTC timestamp
dt = datetime.datetime.fromtimestamp(original_timestamp / 1000.0)

# Print the results
print(f"Reconstructed NonceMs: {nonceMs}")
print(f"Reconstructed NonceRnd: {nonceRnd}")
print(f"Reconstructed NonceSec: {nonceSec}")
print(f"Reconstructed Timestamp (milliseconds): {original_timestamp}")
print(f"Human-readable UTC timestamp: {dt}")