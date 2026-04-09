from storage import make_fresh_users_db, save_users_db
from ui import print_menu, print_packet
from protocol import (merkle_setup, server_make_challenge, client_login_sign, server_verify_login,
                      server_eceg_keys_generator, ecc_pubkey_brief, do_one_transaction, point_to_bytes)

def main():
    with open("transaction.txt", "r", encoding="utf-8") as f: #load transaction data format
        template = f.read()  
        
    usernames = ["alice", "bob", "charlie"] #local db for simulation
    db, client_state = make_fresh_users_db(usernames, merkle_setup, N=64)
    print("\nCreated fresh users_db.json for this run.\n")
    
    while True:
        # user authentication
        print("\n=== LOGIN ===")
        username = input("Username (alice/bob/charlie) or 'q' to quit: ").strip()
        print()
        if username.lower() == "q": #handle login
            print("Goodbye.")
            return 0
        if username not in db:
            print("Unknown username.")
            continue
        
        # client-side secrets for this run
        N=db[username]["N"]
        key_pairs = client_state[username]["key_pairs"]
        mk = client_state[username]["mk"]
        next_i = client_state[username]["next_i"]
        
        
        #server makes challege to user to proof authenticity
        challenge = server_make_challenge()
        print(" Server: made a challenge for user to proof authenticity")
        i = next_i
        next_i += 1
        sig = client_login_sign(challenge, i, key_pairs, mk) #sign the challenge
        print(" Client: client signed challege.")
        ok = server_verify_login(db, username, i, challenge, sig) #verify sign
        if not ok:
            print("Authentication failed. Exiting.")
            break
        
        save_users_db(db)
        used_indices = set(db[username]["used_indices"]) #sync used indices after login
        
        # session ec-el-gamal keys
        server_eceg_keyset = server_eceg_keys_generator() #server generates eceg keys
        client_eceg_key = server_eceg_keyset.public_key() #client got eceg public key
        server_eceg_secret = server_eceg_keyset.secret_key() #server keeps the secret key
        server_root = bytes.fromhex(db[username]["merkle_root_hex"])
        print(" Session: server generated EC-ElGamal keys and sent pk to client.")
        
        tx_history = []
        last_tx = None  # will store last transaction details
                
        while True:
            print_menu()
            choice = input("Choose option: ").strip()
            
            if choice == "1":  # Make transaction(s)
                while True:
                    next_i, tx, used_indices, packet = do_one_transaction(
                        template, username, N, key_pairs, mk,
                        client_eceg_key, server_eceg_secret,
                        server_root, used_indices, next_i)
            
                    if tx is not None:
                        last_tx = tx
                        tx_history.append(tx)
            
                    # persist used indices + next_i
                    db[username]["used_indices"] = sorted(list(used_indices))
                    save_users_db(db)
                    client_state[username]["next_i"] = next_i
            
                    ans = input("\nView Packet sent? (y/n): ").strip().lower()
                    if ans == "y":
                        print_packet(packet, point_to_bytes)
            
                    ans = input("\nAnother transaction? (y/n): ").strip().lower()
                    print("")
                    if ans != "y":
                        print("Returning to menu.")
                        break
            
            elif choice == "2":
                if not last_tx:
                    print("\nNo transaction yet.\n")
                    continue
                print("\n=== LAST TRANSACTION: Salsa20 values ===")
                print(f"i: {last_tx['i']}")
                print(f"nonce (hex): {last_tx['nonce_hex']}")
                print(f"salsa key Ks (hex): {last_tx['salsa_ks_hex']}")
                print(f"cipher (hex): {last_tx['cipher_hex']}")
                print()
            
            elif choice == "3":
                if not tx_history:
                    print("\nNo transactions yet.\n")
                    continue
                print("\n=== TRANSACTION HISTORY ===")
                for idx, tx in enumerate(tx_history, start=1):
                    print(f"\n--- #{idx} ---")
                    print(f"time_utc: {tx['time_utc']}")
                    print(f"i: {tx['i']}")
                    print(f"plaintext:\n{tx['plaintext']}")
                    print(f"cipher (hex): {tx['cipher_hex']}")
                print()
            
            elif choice == "4":
                print("\n=== Lamport/Merkle KeySet ===")
                print(f"N (Lamport one-time keys): {N}")
                print(f"next_i (next unused index): {next_i}")
                print(f"used_indices_count: {len(used_indices)}")
                if tx_history:
                    print(f"last_used_i: {tx_history[-1]['i']}")
                else:
                    print("last_used_i: (none yet)")
                print()
            
            elif choice == "5":
                print("\n=== Merkle Root (hex) ===")
                print(db[username]["merkle_root_hex"])
                print()
            
            elif choice == "6":
                print("\n=== EC El-Gamal KeySet ===")
                print("Public key (pk):")
                pk_info = ecc_pubkey_brief(client_eceg_key)
                print(f" curve: {pk_info['curve']} p_bits: {pk_info['p_bits']}")
                print(f" x: {pk_info['x']}")
                print(f" y: {pk_info['y']}")
                print("\nSecret key (sk):")
                # server_eceg_sk is usually an int in ecc libs
                print(f" sk: {server_eceg_secret}")
                print()
            
            elif choice == "7":
                print("\n=== used_i ===")
                print(sorted(list(used_indices)))
                print()
            
            elif choice == "8":
                print("\nLogged out.\n")
                # persist session next_i
                client_state[username]["next_i"] = next_i
                break
            
            elif choice == "9":
                print("\nExiting program.\n")
                return 0
            else:
                print("\nInvalid choice.\n")


if __name__ == "__main__":
    main()        