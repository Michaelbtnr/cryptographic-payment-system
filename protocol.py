import hashlib
import random, string
import secrets
import ecc   # Eliptic Curve El-Gamal implementation
import merkle_tree_master as mt   # Merkle Tree using Lamport ds implementation
from salsa20 import salsa20_xor as salsa20   #salsa20 wrapper implementation, using salsa20 core
from datetime import datetime
from zoneinfo import ZoneInfo

class ECEGKeySet: #class to handle how eceg implemantaion returns the keyset.
    def __init__(self, curve, sk, pk):
        self.curve = curve
        self.sk = sk
        self.pk = pk
    def secret_key(self):
        return self.sk #sk is secret key
    def public_key(self):
        return self.pk

def server_make_challenge() -> bytes: #generates challenge for client
    return secrets.token_bytes(32)

def client_login_sign(challenge: bytes, i: int, key_pairs, mk):
    # message to sign: H("login" || challenge)
    digest = hashlib.sha256(b"login|" + challenge).digest()
    M = digest.hex()
    sig = client_merkle_sign(M, i, key_pairs, mk)
    return sig

def server_verify_login(db, username: str, i: int, challenge: bytes, sig) -> bool:
    if username not in db:
        print(" Server: unknown username.")
        return False
    user = db[username]
    N = user["N"]
    merkle_root = bytes.fromhex(user["merkle_root_hex"]) 
    used = set(user["used_indices"])

    if not (0 <= i < N):
        print(" Server: login rejected (index out of range).")
        return False
    if i in used:
        print(" Server: login rejected (index reused).")
        return False

    # recompute what M MUST be for this challenge
    expected_M = hashlib.sha256(b"login|" + challenge).hexdigest()

    if not server_merkle_verify(expected_M, sig, merkle_root, N, i):
        print(" Server: login rejected (bad signature).")
        return False

    used.add(i)
    user["used_indices"] = sorted(list(used))
    print(" Server: login accepted. authenticity proved.")
    return True

def client_message_encryption(client_salsa_ks, nonce, plaintext_bytes):
    #encrypt the message using Salsa20
    cipher = salsa20(client_salsa_ks, nonce, plaintext_bytes)
    return cipher

def client_key_eceg_encryption(pk_ec, ks):
    #encrypt Salsa20 key with EC El-Gamal key encryption
    # ec-eg encrypts a curve Point
    Ks_point = ecc.encode(ks, pk_ec.curve) # encode Ks into a point.
    c1, c2 = ecc.elgamal_encrypt(Ks_point, pk_ec) # Point -> (Point, Point)
    enc_ks = (c1, c2)
    return enc_ks

#serialize ECC points deterministically (needed for hashing)
def point_to_bytes(P) -> bytes:
    # fixed length based on curve prime p
    blen = (P.curve.p.bit_length() + 7) // 8
    return int(P.x).to_bytes(blen, "big") + int(P.y).to_bytes(blen, "big")
def encKs_to_bytes(enc_ks) -> bytes:
    c1, c2 = enc_ks
    return point_to_bytes(c1) + point_to_bytes(c2)

def merkle_setup(N: int):
    # N must be power of 2
    key_pairs = [mt.LamportSignature() for _ in range(N)] # N unique key pairs. each Lamport public key becomes one leaf
    mk = mt.MerkleTree(n_leaves=N) #create empty tree

    for i in range(N):
        # leaf = H(concat(public_key_i))
        mk.add_node(key_pairs[i].get_key('public', concatenate=True), (0, i), hashed=False)

    mk.generate_tree() # builds the Merkle tree upward. level 0 are leafs
    root = mk.get_root()  # Merkle public key
    return key_pairs, mk, root

def client_merkle_sign(message_str: str, i: int, key_pairs, mk): #signs one message using i-th lamport one time key
    sig_prime = key_pairs[i].sign(message_str) # sign with lamport private key 'i'
    Yi_bytes = key_pairs[i].get_key('public', concatenate=True) # public key to the private key used. serialized into one byte string.
    auth = mk.get_authentification_path_hashes(i) # Merkle authentication path (Merkle proof) for leaf 'i'
    return [sig_prime, Yi_bytes, auth] #[lamport sign, lamport public key, merkle proof]


def server_eceg_keys_generator(): #generates (secret key, public key)
    curve = ecc.M383 #Using curve M383 Prime because it can hold ~383 bits which is ~47bytes > 32bytes(salsa key)
    sk_ec, pk_ec = ecc.gen_key_pair(curve)
    return ECEGKeySet(curve, sk_ec, pk_ec)


def server_merkle_verify(message_str: str, sig, merkle_root: bytes, N: int, i: int) -> bool:
    #code based of merkle_tree_master/flow_refrence.py
    print(" Server: Verifying client's authenticity")
    sig_prime, Yi_bytes, auth_hashes = sig
    Yi_list = mt.LamportSignature.decatenate_key(Yi_bytes) # verify Lamport signature using Yi
    
    if not mt.LamportSignature.verify(message_str, sig_prime, Yi_list):
        return False
    mk_receiver = mt.MerkleTree(n_leaves=N) # verify Merkle auth path matches the stored root
    mk_receiver.add_node(Yi_bytes, (0, i), hashed=False)
    mk_receiver.generate_tree()

    for j, (level, index) in enumerate(mk_receiver.get_authentification_path(i)):
        mk_receiver.add_node(auth_hashes[j], (level, index), hashed=True)
    mk_receiver.generate_tree()
    return mk_receiver.get_root() == merkle_root

def server_process_transaction(packet, server_root, server_sk_ec, N, used_indices: set):
    #packet is a dictionary: i, nonce, cipher, enc_Ks(c1, c2), signature(sig_prime, Yi_bytes, auth_path_hashes)
    i = packet["i"]
    if not (0 <= i < N): # range protection
        print(" Server: REJECTED (index out of range).")
        return None
    if i in used_indices: # reuse protection
        print(" Server: REJECTED (Lamport index reused).")
        return None
    
    cipher = packet["cipher"]
    enc_ks = packet["enc_ks"]
    signature = packet["sign"]
    nonce = packet["nonce"]

    enc_ks_bytes = encKs_to_bytes(enc_ks) # rebuild message hash M exactly as client
    digest = hashlib.sha256(nonce + cipher + enc_ks_bytes).digest()
    M = digest.hex()

    # verify signature (Lamport + Merkle membership)
    if not server_merkle_verify(M, signature, server_root, N, i):
        print(" Server: REJECTED (bad signature).")
        return None
    else:
        print(" Server: Signature is Authentic.")
    used_indices.add(i) #each i can be used once
    # decrypt Salsa key
    c1, c2 = enc_ks
    Ks_point = ecc.elgamal_decrypt(server_sk_ec, c1, c2)
    Ks = ecc.decode(Ks_point)
    print(" Server: decrypting message...")
    # decrypt message (Salsa20 XOR again)
    plaintext_bytes = salsa20(Ks, nonce, cipher)
    plaintext = plaintext_bytes.decode("utf-8", errors="replace")
    print(" Server: message decrypted.")
    ans = input("\nView decrypted message? (y/n): ").strip().lower()
    if ans == "y":
        print(f"\ndecrypted message: \n{plaintext}\n")
    elif ans=="n":
        print("")
        print(" Server: Continue.")
    
    print(" Server: Transaction ACCEPTED.")
    return plaintext
    
    
def ecc_pubkey_brief(pk):# pk is ecc.Point
    return {
        "curve": getattr(pk.curve, "name", str(pk.curve)),
        "x": int(pk.x),
        "y": int(pk.y),
        "p_bits": pk.curve.p.bit_length()}

def do_one_transaction(template, username, N, key_pairs, mk, client_eceg_pk,
                       server_eceg_sk, server_root, used_indices, next_i):
    ##Performs one full transaction.
    ##Returns: (new_next_i, tx_record, updated_used_indices)
    if next_i >= N:
        print(f" Client: OUT OF LAMPORT KEYS (N={N}). Start a new session.")
        return next_i, None, used_indices

    nonce, plaintext = generate_data(template) # generate data (nonce + plaintext)
    print(f"\nPlain Message:\n{plaintext}\n")

    client_salsa_ks = secrets.token_bytes(32) # client salsa key

    # encrypt plaintext with salsa20
    plaintext_bytes = plaintext.encode("utf-8") #string->bytes
    client_cipher = client_message_encryption(client_salsa_ks, nonce, plaintext_bytes)
    ans = input("\nView encrypted message? (y/n): ").strip().lower()
    if ans == "y":
        print(f"\nencrypted message: \n{client_cipher.hex()}\n")
    elif ans=="n":
        print("")
        print(" Client: Continue.")

    # encrypt Ks with EC-ElGamal
    encrypted_salsa_key = client_key_eceg_encryption(client_eceg_pk, client_salsa_ks)  # (c1,c2)
    print(" Client: encrypting salsa key with eceg.")
    enc_ks_bytes = encKs_to_bytes(encrypted_salsa_key)
    digest = hashlib.sha256(nonce + client_cipher + enc_ks_bytes).digest() #digest M = H(nonce || cipher || EncKsBytes)
    M = digest.hex()
    print(" Client: building transaction hash H(nonce||cipher|| Enc_Ks)")
    ans = input("\nView Hash(SHA-256) digest? (y/n): ").strip().lower()
    if ans == "y":
        print(f"\nDigest: {M}\n")
    elif ans=="n":
        print("")
        print(" Client: Continue.")
    # Sign using Merkle-Lamport index i
    i = next_i
    next_i += 1
    signature = client_merkle_sign(M, i, key_pairs, mk)
    print(" Client: message was signed.")

    # Packet to server
    packet = {"i": i, "nonce": nonce, "cipher": client_cipher, "enc_ks": encrypted_salsa_key, "sign": signature}
    print(" Client: Packet was created & sent to server...\n")
    # Server verify + decrypt
    decrypted_plaintext = server_process_transaction(packet, server_root, server_eceg_sk, N, used_indices)

    if decrypted_plaintext is not None:
        print(" Session: Transaction Complete.")

    tx_record = {
        "time_utc": datetime.utcnow().isoformat(),
        "i": i,
        "nonce_hex": nonce.hex(),
        "salsa_ks_hex": client_salsa_ks.hex(),
        "cipher_hex": client_cipher.hex(),
        "enc_ks_c1": point_to_bytes(encrypted_salsa_key[0]).hex(),
        "enc_ks_c2": point_to_bytes(encrypted_salsa_key[1]).hex(),
        "plaintext": plaintext,
        "server_decrypted": decrypted_plaintext}
    return next_i, tx_record, used_indices, packet


def generate_data(template):
    #generates nonce for encryption and simulation Data (price, 4 last digits, current_time, session_id, customer_id, transaction_id, token_id)
    # *some data is predefined in the template
    price = float(input("Enter price (NIS): "))
    price = f"{price:.2f}"
    digits=input("Enter card 4 last digits: ")
    nonce = secrets.token_bytes(8)  #generate safe nonce for encryption
    session_id = f"sess_id_{random.randint(100, 999)}"
    cust_id = f"CUST-{random.randint(10000, 99999)}"
    tran_id=f"tran-{random.randint(100, 999999)}"
    cards = ["VISA", "MasterCard", "AmericanExpress", "Diners"]
    card = random.choice(cards)
    month = random.randint(1, 12)
    year = random.randint(2027, 2040)
    exp_date = f"{month:02d}/{year}"
    token = "tok_" + "".join(random.sample(string.ascii_lowercase * 5 + string.digits * 5, 10))
    current_time = datetime.now(ZoneInfo("Asia/Jerusalem")).isoformat()# current time for the data
    
    filled_text = template.format(tran_id=tran_id, current_time=current_time, price=price, token=token, card=card,
                                  digits=digits, exp_date=exp_date, cust=cust_id, sess_id=session_id)
    return nonce, filled_text
