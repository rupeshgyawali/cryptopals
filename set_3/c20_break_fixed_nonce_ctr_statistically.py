"""

Challenge 20:

Break fixed-nonce CTR statistically
-----------------------
https://cryptopals.com/sets/3/challenges/20
"""
from typing import List, Tuple

from set_3.c19_break_fixed_nonce_ctr_mode_using_substitutions import produce_ciphertexts

def get_single_long_concatenated_ciphertext(ciphertexts: List[bytes]) -> Tuple[bytes, int]:
    """
    Returns concatenation of the given ciphertexts truncated to a common length of 
    the smallest ciphertext in the list and length of the smallest ciphertext.
    """
    min_length = min(len(ciphertext) for ciphertext in ciphertexts)

    concatenated = b''.join([ciphertext[:min_length] for ciphertext in ciphertexts])

    return concatenated, min_length


if __name__ == '__main__':
    ciphertexts = produce_ciphertexts('set_3/20.txt')
    concatenated_ciphertext, key_length = get_single_long_concatenated_ciphertext(ciphertexts)
    # Now break the concatenated ciphertext as repeating-key xor.
