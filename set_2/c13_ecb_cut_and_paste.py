"""

Challenge 13:

ECB cut-and-paste
-----------------
https://cryptopals.com/sets/2/challenges/13

"""

import os
from typing import Dict

import c9_pkcs7_padding as c9
import c10_cbc_mode as c10

BLOCK_SIZE = 16
RANDOM_KEY = os.urandom(16)

def k_v_parser(data: str) -> Dict[str, str]:
    k_v_pair = data.split('&')

    return {pair.split('=')[0]:pair.split('=')[1] for pair in k_v_pair}

def profile_for(email: str) -> str:
    checked_email = ''.join([ c for c in email if c != '&' and c != '='])
    return f'email={checked_email}&uid=10&role=user'


def encrypt_profile_for(email: str, key: bytes=RANDOM_KEY) -> bytes:
    profile = profile_for(email)
    profile_bytes = bytes(profile, encoding='ascii')
    plaintext = c9.PKCS7_pad(profile_bytes, BLOCK_SIZE)
    return c10.aes_ecb_encrypt(plaintext, key)

def decrypt_profile(encrypted_profile, key: bytes=RANDOM_KEY) -> Dict[str, str]:
    decrypted_profile = c10.aes_ecb_decrypt(encrypted_profile, key)
    profile = c9.PKCS7_unpad(decrypted_profile).decode()

    return k_v_parser(profile)

def make_admin_profile() -> Dict[str, str]:
    # print(profile_for('foo@bar.com'))
    # email=foo@bar.com&uid=10&role=user

    # <-----16bytes--><--------16bytes (admin block)------------------>
    # email=AAAAAAAAAAadmin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b&uid=10&role=user
    playload = 'AAAAAAAAAA' + 'admin' + '\x0b'*11
    ciphertext = encrypt_profile_for(playload)
    admin_block = ciphertext[16:16*2]

    # <-----16bytes--><---16bytes----><---16bytes(admin block)------------------------>
    # email=AAfoo@bar.com&uid=10&role=admin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b
    normal_profile = encrypt_profile_for('AAfoo@bar.com')
    admin_profile_ciphertext = normal_profile[:-16] + admin_block
    admin_profile = decrypt_profile(admin_profile_ciphertext)

    return admin_profile

if __name__ == '__main__':
    admin_profile = make_admin_profile()
    print(admin_profile)
    assert admin_profile.get('role') == 'admin', 'Admin Test Failed!'

