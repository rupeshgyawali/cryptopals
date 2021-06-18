"""

Challenge 24:

Create the MT19937 stream cipher and break it
-----------------------
https://cryptopals.com/sets/3/challenges/24
"""
import os
import random
import string
import time

from set_3.c21_mt19937_rng import MT19937RNG

class MT19937StreamCipher:
    def __init__(self, key: bytes) -> None:
        self._key = key
        self._rng = MT19937RNG()
        self._rng.seed_mt(int.from_bytes(self._key, 'big'))

    def _keystream_generator(self) -> int:
        while True:
            random_number = self._rng.extract_number()
            for i in range(MT19937RNG.W//8):
                yield (random_number >> (MT19937RNG.W - (i+1) * 8)) & 0xff
                
    def encrypt(self, plaintext: bytes) -> bytes:
        return self._encrypt_decrypt(plaintext)

    def decrypt(self, ciphertext: bytes) -> bytes:
        return self._encrypt_decrypt(ciphertext)

    def _encrypt_decrypt(self, text: bytes) -> bytes:
        keystream = self._keystream_generator()
        xor_text = b''
        for byte in text:
            xor_bytes = byte ^ next(keystream)
            xor_text += bytes([xor_bytes])

        return xor_text

def get_ciphertext(message: bytes) -> bytes:
    """
    Returns ciphertext by encrypting message prefexed with random 
    number of random characters, using MT19937 stream cipher.
    """
    key = os.urandom(2) # 16-bits
    
    # For testing
    global KEY_LOG
    KEY_LOG = key

    stream_cipher = MT19937StreamCipher(key)

    random_characters = ''.join(random.choice(string.ascii_uppercase) for _ in range(random.randint(2, 10)))
    plaintext = bytes(random_characters, 'ascii') + message
    ciphertext = stream_cipher.encrypt(plaintext)

    return ciphertext

def crack_key(ciphertext: bytes, message: bytes) -> bytes:
    """
    Returns cracked key using ciphertext and known message.
    """
    # Key size is just 16 bits (too short). So, simple brute force works
    for i in range(2**16):
        key = int.to_bytes(i, 2,'big')
        stream_cipher = MT19937StreamCipher(key)
        plaintext = stream_cipher.decrypt(ciphertext)
        if plaintext.endswith(message):
            return key

def generate_passowrd_reset_token() -> str:
    timestamp = int(time.time())
    key = int.to_bytes(timestamp, 4, 'big') # timestamp is of 4 bytes(32-bits)
    stream_cipher = MT19937StreamCipher(key)

    return stream_cipher.encrypt(b'PasswordResetToken').hex()

def check_reset_token(token: str) -> bool:
    timestamp = int(time.time())
    # Taking token validity period of 1hr(3600 seconds)
    for i in range(3600):
        key = int.to_bytes(timestamp-i, 4, 'big')
        stream_cipher = MT19937StreamCipher(key)
        if stream_cipher.decrypt(bytes.fromhex(token)) == b'PasswordResetToken':
            return True

    return False

if __name__ == '__main__':
    # Test if cipher is working properly
    stream_cipher = MT19937StreamCipher(b'aa')
    plaintext = b'A'*12
    ciphertext = stream_cipher.encrypt(plaintext)
    assert plaintext == MT19937StreamCipher(b'aa').decrypt(ciphertext)

    # Crack key
    message = b'A'*14
    ciphertext = get_ciphertext(message)
    key = crack_key(ciphertext, message)
    assert key == KEY_LOG
    
    # Generate and test token
    token = generate_passowrd_reset_token()
    time.sleep(1)
    print(check_reset_token(token))




