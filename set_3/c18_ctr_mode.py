"""

Challenge 18:

Implement CTR, the stream cipher mode
-----------------------
https://cryptopals.com/sets/3/challenges/18
"""
import base64

from utils.aes import AES, Mode

STRING = 'L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=='
BLOCK_SIZE = 16
KEY = b'YELLOW SUBMARINE'

def aes_ctr_decrypt(ciphertext: bytes, key: bytes, nonce: int = 0) -> bytes:
    cipher = AES(Mode.ECB)
    
    ciphertext_length = len(ciphertext)
    plaintext = b''
    for bytecount in range(0, ciphertext_length, BLOCK_SIZE):
        block_count = bytecount // BLOCK_SIZE
        counter = nonce.to_bytes(64//8, 'little') + block_count.to_bytes(64//8, 'little')
        keystream = cipher.encrypt(counter, key)

        for ciphertext_byte, keystream_byte in \
                    zip(ciphertext[bytecount:bytecount+BLOCK_SIZE], keystream):
            plaintext += bytes([ciphertext_byte ^ keystream_byte])

    return plaintext

if __name__ == '__main__':
    ciphertext = base64.b64decode(STRING)
    plaintext = aes_ctr_decrypt(ciphertext, KEY)
    print(plaintext)
