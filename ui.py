import hashlib

def print_menu(): #Menu
    print("\n--------- MENU ---------")
    print("1. Make a transaction.")
    print("2. view Salsa20 values (last transaction).")
    print("3. view previous transactions (plain + cipher).")
    print("4. Lamport KeySet.")
    print("5. merkle Tree root (hex).")
    print("6. EC El-Gamal KeySet.")
    print("7. view used_i.")
    print("8. Logout (back to login).")
    print("9. Quit.\n")

def print_packet(packet, point_to_bytes):
    i = packet["i"]
    nonce = packet["nonce"]
    cipher = packet["cipher"]
    c1, c2 = packet["enc_ks"]
    sig_prime, Yi_bytes, auth_path = packet["sign"]

    print("\n------ CLIENT -> SERVER PACKET Content ------")
    print(f"Lamport index i        : {i}")
    print(f"nonce (hex)            : {nonce.hex()}")
    print(f"ciphertext (hex)       : {cipher.hex()}")

    print("\nEC-ElGamal encrypted Ks:")
    print(f" c1 (hex)             : {point_to_bytes(c1).hex()}")
    print(f" c2 (hex)             : {point_to_bytes(c2).hex()}")

    print("\nLamport Signature:")
    print(f" sig_prime length     : {len(sig_prime)} bits")
    print(f" Yi (public key) hash : {hashlib.sha256(Yi_bytes).hexdigest()}")

    print("\nMerkle Authentication Path:")
    for idx, h in enumerate(auth_path):
        print(f" level {idx}: {h.hex()}")
    print("=================================\n")
    