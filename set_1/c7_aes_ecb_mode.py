"""

Challenge 7:

AES in ECB mode
---------------
The Base64-encoded content in this file has been encrypted via AES-128 in ECB mode under the key

"YELLOW SUBMARINE".
(case-sensitive, without the quotes; exactly 16 characters; I like "YELLOW SUBMARINE" because it's exactly 16 bytes long, and now you do too).

Decrypt it. You know the key, after all.

Easiest way: use OpenSSL::Cipher and give it AES-128-ECB as the cipher.

Do this with code.
You can obviously decrypt this using the OpenSSL command-line tool, but we're having you get ECB working in code for a reason. You'll need it a lot later on, and not just for attacking ECB.

"""

import sys
import base64

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def aes_ecb_decrypt(cipher_text: bytes, key: bytes) -> bytes:
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
    decryptor = cipher.decryptor()
    
    return decryptor.update(cipher_text) + decryptor.finalize()

def get_cipher_text_from_file(file_name: str) -> bytes:
    with open(file_name, 'r') as f:
        cipher_b64 = f.read()
    cipher_text = base64.b64decode(cipher_b64)

    return cipher_text

if __name__ == '__main__':
    if(len(sys.argv) == 3):
        file_name = sys.argv[1]
        key_string = sys.argv[2]
        cipher_text = get_cipher_text_from_file(file_name)
        key = key_string.encode()
        print(f'Plain Text:\n{aes_ecb_decrypt(cipher_text, key).decode("latin-1")}')
    else:
        print(f'Usage: {sys.argv[0]} <file_name> <key>')

