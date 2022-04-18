import os
import base64

from utils.aes import AES, Mode
from utils.xor import xor

KEY = os.urandom(16)

def edit_api(ciphertext: bytes, offset: int, newtext: bytes) -> bytes:
    """Return the modified ciphertext"""
    return _edit_ciphertext(ciphertext, KEY, offset, newtext)

def _edit_ciphertext(ciphertext: bytes, key: bytes, offset: int, newtext: bytes) -> bytes:
    cipher = AES(Mode.CTR)
    plaintext = cipher.decrypt(ciphertext, key)
    new_plaintext = plaintext[:offset] + newtext + plaintext[offset + len(newtext):]
    return cipher.encrypt(new_plaintext, key)

def get_ciphertext(filename: str) -> bytes:
    """Return ciphertext by CTR mode encryption of the recovered plaintext 
    from ecb encrypted ciphertext (under the key "YELLOW SUBMARINE") in the 
    given file.
    """
    with open(filename, 'r') as f:
        ecb_ciphertext_b64 = f.read()
    ecb_ciphertext = base64.b64decode(ecb_ciphertext_b64)

    ecb_cipher = AES(Mode.ECB)
    plaintext = ecb_cipher.decrypt(ecb_ciphertext, b'YELLOW SUBMARINE')
    # Only for testing
    global PLAINTEXT_LOG
    PLAINTEXT_LOG = plaintext

    ctr_cipher = AES(Mode.CTR)
    return ctr_cipher.encrypt(plaintext, KEY)


if __name__ == '__main__':
    ciphertext = get_ciphertext('set_4/25.txt')

    edited_ciphertext = edit_api(ciphertext, 0, b'A'*len(ciphertext))
    keystream = xor(edited_ciphertext, b'A'*len(ciphertext))
    recovered_plaintext = xor(ciphertext, keystream)

    # # We can also directly recover keystream by passing sequence of byte 0
    # keystream = edit_api(ciphertext, 0, b'\x00'*len(ciphertext))
    # recovered_plaintext = xor(ciphertext, keystream)

    # # We can also directly recover plaintext by passing ciphertext
    # recovered_plaintext = edit_api(ciphertext, 0, ciphertext)

    assert recovered_plaintext == PLAINTEXT_LOG, "Failed!"
    print(recovered_plaintext)