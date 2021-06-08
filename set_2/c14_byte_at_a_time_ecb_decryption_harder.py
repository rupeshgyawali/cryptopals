"""

Challenge 14:

Byte-at-a-time ECB decryption (Harder)
--------------------------------------
https://cryptopals.com/sets/2/challenges/14

"""

import os
import random
from typing import Callable, List, Tuple

import c9_pkcs7_padding as c9
import c10_cbc_mode as c10
import c12_byte_at_a_time_ecb_decryption_simple as c12

BLOCK_SIZE = 16
RANDOM_KEY = os.urandom(16)
RANDOM_PREFIX = os.urandom(random.randint(10, 50))
# RANDOM_PREFIX = b'riririri'

def encryption_oracle(message: bytes) -> bytes:
    key = RANDOM_KEY
    append_text = c12.get_unknown_string()
    plaintext = RANDOM_PREFIX + message + append_text
    plaintext = c9.PKCS7_pad(plaintext, BLOCK_SIZE)

    ciphertext = c10.aes_ecb_encrypt(plaintext, key)

    return ciphertext

def construct_check_dictionary(oracle: Callable[[bytes], bytes], 
        block_size: int, one_byte_short_block: bytes, 
        start_block_no: int, start_prefix: bytes) -> List[bytes]:
    prefix_blocks_size = start_block_no * block_size
    check_dictionary = []
    for i in range(256):
        slice_ = slice(prefix_blocks_size, prefix_blocks_size+block_size)
        check_dictionary.append(oracle(start_prefix + one_byte_short_block+bytes([i]))[slice_])

    return check_dictionary

def get_starting_block_and_prefix(oracle: Callable[[bytes], bytes], block_size: int) -> Tuple[int, bytes]:
    cipher = oracle(b'')
    previous_blocks = [cipher[i:i+block_size] for i in range(0, len(cipher), block_size)]
    for i in range(block_size):
        oracle_input = b'A' * (i+1)
        oracle_output = oracle(oracle_input)
        blocks = [oracle_output[i:i+block_size] for i in range(0, len(oracle_output), block_size)]
        same_blocks = [b1 for b1, b2 in zip(blocks, previous_blocks) if b1 == b2]
        previous_blocks = blocks
        if i == 0:
            previous_same_no = len(same_blocks)
            start_block_no = previous_same_no
            start_prefix = b''
        if previous_same_no < len(same_blocks):
            start_block_no = previous_same_no + 1
            start_prefix = b'a' * i
            break
        previous_same_no = len(same_blocks)

    return start_block_no, start_prefix

def crack_unknown_string(oracle: Callable[[bytes], bytes], block_size: int) -> bytes:
    # start_block_no is the block number from where we start similar to challenge 12 and start_prefix
    # is the text which when prefixed to playload generates fixed blocks for prefixed random bytes.
    start_block_no, start_prefix = get_starting_block_and_prefix(oracle, block_size)
    prefix_blocks_size = start_block_no * block_size

    unknown_string = b''
    unknown_string_length = len(oracle(start_prefix)) - prefix_blocks_size
    for i in range(1, unknown_string_length+1):
        i_byte_short_playload = b'A' * (unknown_string_length - i)
        cipher_block_slice = slice(prefix_blocks_size+unknown_string_length-block_size, 
                                   unknown_string_length+prefix_blocks_size)
        cipher_block = oracle(start_prefix + i_byte_short_playload)[cipher_block_slice]
        
        one_byte_short_block = i_byte_short_playload + unknown_string
        check_dictionary = construct_check_dictionary(oracle, block_size, one_byte_short_block[-block_size+1:], start_block_no, start_prefix)
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
    
    block_size = c12.get_block_size(oracle)
    print(f'Block Size: {block_size}')

    # check if ECB
    playload = b'A' * block_size * 3
    ciphertext = oracle(playload)
    ecb = c12.is_ecb(ciphertext, block_size)
    print(f'Is ECB?: {ecb}')

    if ecb:
        unknown_string = crack_unknown_string(oracle, block_size)
        print(f'Unknown String: {unknown_string}')
