"""

Challenge 12:

Byte-at-a-time ECB decryption (Simple)
--------------------------------------
https://cryptopals.com/sets/2/challenges/12

"""

import os
import base64
from typing import Callable, List

import c9_pkcs7_padding as c9
import c10_cbc_mode as c10

BLOCK_SIZE = 16
RANDOM_KEY = os.urandom(16)

def get_unknown_string() -> bytes:
    b64_string = """Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
                    aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
                    dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
                    YnkK
                    """

    return base64.b64decode(b64_string)

def encryption_oracle(message: bytes) -> bytes:
    key = RANDOM_KEY
    unknown_string = get_unknown_string()
    plaintext = message + unknown_string
    plaintext = c9.PKCS7_pad(plaintext, BLOCK_SIZE)
    
    ciphertext = c10.aes_ecb_encrypt(plaintext, key)

    return ciphertext

def get_block_size(oracle: Callable[[bytes], bytes]) -> int:
    i = 1
    initail_length = len(oracle(b''))
    while True:
        ciphertext = oracle(b'A'*i)
        ciphertext_length = len(ciphertext)
        if ciphertext_length != initail_length:
            break
        i += 1
    
    return ciphertext_length - initail_length

def is_ecb(ciphertext: bytes, block_size: int) -> bool:
    no_of_blocks = len(ciphertext)//block_size
    blocks = [ciphertext[i*block_size:(i+1)*block_size] for i in range(no_of_blocks)]

    if len(blocks) != len(set(blocks)):
        return True
    return False

def construct_check_dictionary(oracle: Callable[[bytes], bytes], 
        block_size: int, one_byte_short_block: bytes) -> List[bytes]:
    check_dictionary = []
    for i in range(256):
        check_dictionary.append(oracle(one_byte_short_block+bytes([i]))[:block_size])

    return check_dictionary

def crack_unknown_string(oracle: Callable[[bytes], bytes], block_size: int) -> bytes:
    unknown_string = b''
    unknown_string_length = len(oracle(b''))
    for i in range(1, unknown_string_length+1):
        i_byte_short_playload = b'A' * (unknown_string_length - i)
        cipher_block = oracle(i_byte_short_playload)[unknown_string_length-block_size:unknown_string_length]
        
        one_byte_short_block = (i_byte_short_playload + unknown_string)[-block_size+1:]
        check_dictionary = construct_check_dictionary(oracle, block_size, one_byte_short_block)
        try:
            ith_byte = check_dictionary.index(cipher_block)
            unknown_string += bytes([ith_byte])
        except ValueError:
            # for padding bytes values doesnot match as padding bytes changes 
            # with decrease in length.
            pass

    return unknown_string
    
if __name__ == '__main__':
    oracle = encryption_oracle
    
    block_size = get_block_size(oracle)
    print(f'Block Size: {block_size}')

    # check if ECB
    playload = b'A' * block_size * 2
    ciphertext = oracle(playload)
    ecb = is_ecb(ciphertext, block_size)
    print(f'Is ECB?: {ecb}')

    if ecb:
        unknown_string = crack_unknown_string(oracle, block_size)
        print(f'Unknown String: {unknown_string}')

