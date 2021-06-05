"""

Challenge 11:

An ECB/CBC detection oracle
----------------------------
Now that you have ECB and CBC working:

Write a function to generate a random AES key; that's just 16 random bytes.

Write a function that encrypts data under an unknown key --- that is, a function that generates a random key and encrypts under it.

The function should look like:

encryption_oracle(your-input)
=> [MEANINGLESS JIBBER JABBER]
Under the hood, have the function append 5-10 bytes (count chosen randomly) before the plaintext and 5-10 bytes after the plaintext.

Now, have the function choose to encrypt under ECB 1/2 the time, and under CBC the other half (just use random IVs each time for CBC). Use rand(2) to decide which to use.

Detect the block cipher mode the function is using each time. You should end up with a piece of code that, pointed at a block box that might be encrypting ECB or CBC, tells you which one is happening.

"""

import os
import random
from typing import Callable

import c10_cbc_mode as c10
import c9_pkcs7_padding as c9

BLOCK_SIZE = 16

ORACLE_ENCRYPTION_MODE_LOG = []

def generate_random_key(key_length: int = 16) -> bytes:
    return os.urandom(key_length)

def encryption_oracle(message: bytes) -> bytes:
    key = generate_random_key()
    iv = os.urandom(BLOCK_SIZE)

    count = random.randint(5,10)
    plaintext = os.urandom(count) + message + os.urandom(count)
    plaintext = c9.PKCS7_pad(plaintext, BLOCK_SIZE)

    mode = random.randint(0,1)
    # print(mode, end=' ')
    if mode == 1:
        ciphertext = c10.aes_ecb_encrypt(plaintext, key)
        ORACLE_ENCRYPTION_MODE_LOG.append('ECB')
    else:
        ciphertext = c10.aes_cbc_encrypt(plaintext, key, iv)
        ORACLE_ENCRYPTION_MODE_LOG.append('CBC')
    
    return ciphertext

def is_ecb_or_cbc(ciphertext: bytes, block_size: int = BLOCK_SIZE) -> str:
    """
    Returns whether the given cipher text is ECB encrypted or CBC.
    """
    no_of_blocks = len(ciphertext)//block_size
    blocks = [ ciphertext[i*block_size:(i+1)*block_size] for i in range(no_of_blocks) ]

    if len(blocks) == len(set(blocks)):
        return 'CBC'
    return 'ECB'

def detect_oracle_encryption_mode(oracle: Callable[[bytes], bytes]) -> str:
    # payload length at least 3 times the block size length
    payload = b'A'*BLOCK_SIZE*3
    ciphertext = oracle(payload)

    return is_ecb_or_cbc(ciphertext)

if __name__ == '__main__':
    oracle = encryption_oracle

    detected_modes = []
    for i in range(10):
        detected_modes.append(detect_oracle_encryption_mode(oracle))
    print(detected_modes)
    
    assert detected_modes == ORACLE_ENCRYPTION_MODE_LOG
