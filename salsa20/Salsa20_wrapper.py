from .Salsa20 import Salsa
"""Salsa20 Wrapper implemented by Michael Butnaru"""
"""This wrapper is using an official Salsa20 core implementation by Daniel J. Bernstein in Python2"""

def _words_to_bytes_le(words16):
    #converts 16 words (chunk) to 64 bytes
    out = bytearray()
    for w in words16:
        out.extend(int(w & 0xffffffff).to_bytes(4, "little"))
    return bytes(out)  # 64 bytes keystream

def salsa20_xor(key: bytes, nonce: bytes, data: bytes, rounds: int = 20) -> bytes:
    # encrypt/decrypt (symmetric) using salsa20 by XORing data with salsa20 keystream
    # key: 32 bytes
    # nonce: 8 bytes
    
    # input check
    if not isinstance(key, (bytes, bytearray)) or len(key) != 32:
        raise ValueError("Salsa20 key must be 32 bytes.")
    if not isinstance(nonce, (bytes, bytearray)) or len(nonce) != 8:
        raise ValueError("Salsa20 nonce must be 8 bytes.")
    if not isinstance(data, (bytes, bytearray)):
        raise ValueError("Data must be bytes.")

    salsa = Salsa(r=rounds)

    out = bytearray(len(data)) # cipher bytes
    offset = 0 # tracks position in message
    counter = 0 # keystream block generating counter

    while offset < len(data): # Loop over 64-byte blocks
        # block_counter is 8 bytes; simplest is 64-bit little-endian counter
        block_counter = counter.to_bytes(8, "little")

        # salsa expects lists of ints (0..255)
        state = salsa(list(key), list(nonce), list(block_counter)) #16 word state
        keystream = _words_to_bytes_le(state)  # convert to 64 bytes

        chunk = data[offset:offset + 64] # XOR single chunk, up to 64 bytes
        for i, b in enumerate(chunk):
            out[offset + i] = b ^ keystream[i]
            
        offset += len(chunk) #next block
        counter += 1 

    return bytes(out)
