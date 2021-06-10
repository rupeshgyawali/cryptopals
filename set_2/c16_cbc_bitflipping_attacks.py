"""

Challenge 16:

CBC bitflipping attacks
-----------------------
https://cryptopals.com/sets/2/challenges/16
"""
import os

import c9_pkcs7_padding as c9
import c10_cbc_mode as c10

BLOCK_SIZE = 16
RANDOM_KEY = os.urandom(16)
IV = bytes(BLOCK_SIZE)

def encrypt(userdata: bytes) -> bytes:
    prepend = b'comment1=cooking%20MCs;userdata='
    append = b';comment2=%20like%20a%20pound%20of%20bacon'
    escaped_userdata = userdata.replace(b';', b'\\;').replace(b'=', b'\\=')
    data = prepend + escaped_userdata + append
    plaintext = c9.PKCS7_pad(data, BLOCK_SIZE)

    encrypted_data = c10.aes_cbc_encrypt(plaintext, RANDOM_KEY, iv=IV)

    return encrypted_data

def is_admin(ciphertext: bytes) -> bool:
    decrypted_data = c10.aes_cbc_decrypt(ciphertext, RANDOM_KEY, iv=IV)
    data = decrypted_data.split(b';')
    if b'admin=true' in data:
        return True

    return False

def get_userdata_block_number() -> int:
    """Returns the block number which contains user provided data"""
    initial_ciphertext = encrypt(b'A')
    initial_cipher_blocks = [initial_ciphertext[i:i+BLOCK_SIZE] for i in range(0, len(initial_ciphertext), BLOCK_SIZE)]

    next_ciphertext = encrypt(b'B')
    next_cipher_blocks = [next_ciphertext[i:i+BLOCK_SIZE] for i in range(0, len(next_ciphertext), BLOCK_SIZE)]

    userdata_block_number = 0
    for initial_block, next_block in zip(initial_cipher_blocks, next_cipher_blocks):
        if initial_block != next_block:
            break
        else:
            userdata_block_number += 1
    
    return userdata_block_number

def get_playload_prefix(userdata_block_no: int) -> bytes:
    previous_userdata_block = encrypt(b'')[userdata_block_no*BLOCK_SIZE:(userdata_block_no+1)*BLOCK_SIZE]
    prefix_no = 0
    for i in range(BLOCK_SIZE):
        prefix = b'A' * (i+1)
        userdata_block = encrypt(prefix)[userdata_block_no*BLOCK_SIZE:(userdata_block_no+1)*BLOCK_SIZE]
        if previous_userdata_block == userdata_block:
            prefix_no = i
            break
        previous_userdata_block = userdata_block

    return b'A' * prefix_no

def get_modified_ciphertext() -> bytes:
    userdata_block_number = get_userdata_block_number()
    playload_prefix = get_playload_prefix(userdata_block_number)
    
    playload = playload_prefix + b'A' * BLOCK_SIZE + b'?admin?true'
    ciphertext = encrypt(playload)
    cipher_blocks = [ciphertext[i:i+BLOCK_SIZE] for i in range(0, len(ciphertext), BLOCK_SIZE)]

    if playload_prefix:
        substitution_block_no = userdata_block_number + 1
    else:
        substitution_block_no = userdata_block_number
    
    # xor of ';' and '?' gives the bits to flip '?' to ';'
    bit_flip_mask = c10.byte_xor(b';',b'?') + b'\x00'*5 + c10.byte_xor(b'=', b'?') + b'\x00' * (BLOCK_SIZE-7)

    substitution_block = c10.byte_xor(cipher_blocks[substitution_block_no], bit_flip_mask)
    modified_ciphertext = b''.join(cipher_blocks[:substitution_block_no] 
                                   + [substitution_block] 
                                   + cipher_blocks[substitution_block_no+1:]
                                )
    
    return modified_ciphertext

if __name__ == '__main__':
    ciphertext = encrypt(b'A' * BLOCK_SIZE + b'?admin?true')
    admin = is_admin(ciphertext)
    print(f'Is Admin: {admin}')

    modified_ciphertext = get_modified_ciphertext()
    admin = is_admin(modified_ciphertext)
    print(f'Is Admin: {admin}')
    assert admin == True, 'Admin Test Failed!'
