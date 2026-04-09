import json
from pathlib import Path

USERS_DB_PATH = Path("users_db.json")


def make_fresh_users_db(usernames, merkle_setup_func, N=64):
    # creates a fresh DB. generates Merkle roots for each username
    db = {}
    client_state = {}

    for u in usernames:
        key_pairs, mk, merkle_root = merkle_setup_func(N)
        db[u] = {
            "N": N,
            "merkle_root_hex": merkle_root.hex(),
            "used_indices": []
        }
        client_state[u] = {
            "key_pairs": key_pairs,
            "mk": mk,
            "next_i": 0
        }
    USERS_DB_PATH.write_text(json.dumps(db, indent=2), encoding="utf-8")
    return db, client_state

def load_users_db(): #load JSON
    if not USERS_DB_PATH.exists():
        return {}
    return json.loads(USERS_DB_PATH.read_text(encoding="utf-8"))

def save_users_db(db): #to update the db when indice is used
    USERS_DB_PATH.write_text(json.dumps(db, indent=2), encoding="utf-8")