"""

Challenge 19:

Break fixed-nonce CTR mode using substitutions
-----------------------
https://cryptopals.com/sets/3/challenges/19
"""
import os
import base64
from typing import List

from utils.aes import AES, Mode

def produce_ciphertexts(filename: str) -> List[bytes]:
    """
    Returns a list of AES CTR mode encrypted (with a random key and 
    fixed nonce value of 0) ciphertext bytes for each base64 encoded 
    plaintext in the file.
    """
    ciphertexts = []
    key = os.urandom(16)
    cipher = AES(Mode.CTR)
    with open(filename, 'r') as f:
        for line in f:
            plaintext = base64.b64decode(line)
            ciphertext = cipher.encrypt(plaintext, key)
            ciphertexts.append(ciphertext)
    
    return ciphertexts

if __name__ == '__main__':
    ciphertexts = produce_ciphertexts('set_3/19.txt')
    print(ciphertexts)
    # This challenge expects us to break it manually. Guessing letters, validating guesses

