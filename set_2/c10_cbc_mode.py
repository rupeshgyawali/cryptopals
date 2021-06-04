"""

Challenge 10:

Implement CBC mode
------------------
CBC mode is a block cipher mode that allows us to encrypt irregularly-sized messages, despite the fact that a block cipher natively only transforms individual blocks.

In CBC mode, each ciphertext block is added to the next plaintext block before the next call to the cipher core.

The first plaintext block, which has no associated previous ciphertext block, is added to a "fake 0th ciphertext block" called the initialization vector, or IV.

Implement CBC mode by hand by taking the ECB function you wrote earlier, making it encrypt instead of decrypt (verify this by decrypting whatever you encrypt to test), and using your XOR function from the previous exercise to combine them.

The file here is intelligible (somewhat) when CBC decrypted against "YELLOW SUBMARINE" with an IV of all ASCII 0 (\x00\x00\x00 &c)

Don't cheat.
Do not use OpenSSL's CBC code to do CBC mode, even to verify your results. What's the point of even doing this stuff if you aren't going to learn from it?

"""

import os
import base64

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

import c9_pkcs7_padding as c9

BLOCK_SIZE = 16

file_name = 'set_2/10.txt'
key = b'YELLOW SUBMARINE'
IV = bytes(BLOCK_SIZE) # ASCII 0 (\x00) bytes

def byte_xor(byte_one: bytes, byte_two: bytes) -> bytes:
    x1 = int.from_bytes(byte_one, 'big')
    x2 = int.from_bytes(byte_two, 'big')
    y = x1 ^ x2
    return y.to_bytes(len(byte_one), 'big')

def aes_ecb_encrypt(message: bytes, key: bytes) -> bytes:
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
    encryptor = cipher.encryptor()

    return encryptor.update(message) + encryptor.finalize()

def aes_ecb_decrypt(cipher_text: bytes, key: bytes) -> bytes:
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
    decryptor = cipher.decryptor()

    return decryptor.update(cipher_text) + decryptor.finalize()

def aes_cbc_encrypt(message: bytes, key: bytes, iv: bytes = None) -> bytes:
    if iv is None:
        iv = os.urandom(16)
    if len(key) != 16:
        raise ValueError('Key must be of 16 bytes')
    if len(iv) != 16:
        raise ValueError('IV must be of 16 bytes')
    
    plain_text = c9.PKCS7_pad(message, BLOCK_SIZE)

    cipher_text = bytes()
    previous_cipher_block = iv
    no_of_blocks = len(plain_text)//BLOCK_SIZE
    for i in range(no_of_blocks):
        current_block = plain_text[i*BLOCK_SIZE:(i+1)*BLOCK_SIZE]
        addition_block = byte_xor(current_block, previous_cipher_block)
        cipher_block = aes_ecb_encrypt(addition_block, key)
        previous_cipher_block = cipher_block
        cipher_text += cipher_block
    
    return cipher_text

def aes_cbc_decrypt(cipher_text: bytes, key: bytes, iv: bytes) -> bytes:
    if len(key) != 16:
        raise ValueError('Key must be of 16 bytes')
    if len(iv) != 16:
        raise ValueError('IV must be of 16 bytes')
    
    plain_text = bytes()
    previous_block = iv
    no_of_blocks = len(cipher_text)//BLOCK_SIZE
    for i in range(no_of_blocks):
        current_block = cipher_text[i*BLOCK_SIZE:(i+1)*BLOCK_SIZE]
        ecb_plain_text = aes_ecb_decrypt(current_block, key)
        plain_text += byte_xor(ecb_plain_text, previous_block)
        previous_block = current_block

    plain_text = c9.PKCS7_unpad(plain_text)
    
    return plain_text
        
def get_cipher_text_from_file(file_name: str) -> bytes:
    with open(file_name, 'r') as f:
        cipher_b64 = f.read()
    cipher_text = base64.b64decode(cipher_b64)

    return cipher_text

if __name__ == '__main__':
    cipher_text = get_cipher_text_from_file(file_name)
    message = aes_cbc_decrypt(cipher_text, key, iv=IV)
    print(message)
    assert cipher_text == aes_cbc_encrypt(message, key, iv=IV)
