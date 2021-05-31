"""

Challenge 3:

Single-byte XOR cipher
----------------------
The hex encoded string:

1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736
... has been XOR'd against a single character. Find the key, decrypt the message.

You can do this by hand. But don't: write code to do it for you.

How? Devise some method for "scoring" a piece of English plaintext. Character frequency is a good metric. Evaluate each output and choose the one with the best score.

Achievement Unlocked
You now have our permission to make "ETAOIN SHRDLU" jokes on Twitter.

"""

import sys
import string
from typing import Tuple

hex_string = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
test_output = 'Cooking MC\'s like a pound of bacon'

def single_byte_xor(msg_bytes: bytes, key_byte: bytes) -> bytes:
    xor_ed = bytes()
    for byte in msg_bytes:
        xor_ed += bytes([byte ^ int.from_bytes(key_byte, 'big')])
    return xor_ed

def decode_hex(hex_string: str) -> bytes:
    x = int(hex_string, 16)
    return x.to_bytes((x.bit_length() + 7)//8, byteorder='big')

def text_score(text: str) -> int:
    """
    Return the score representing how likely the given text is 
    valid english text.
    """
    # TODO: Look for better text scoring algorithms.
    text_length = len(text)
    frequency_order = 'etaoinsrhldcumfpgwybvkxjqz'
    score = 0
    for c in text:
        pos = frequency_order.find(c.lower())
        if(pos == -1):
            score += pos
        else:
            score += (text_length - pos)
    
    return score

def crack_single_byte_xor_cipher(cipher_hex: str) -> Tuple[str, str, int]:
    """
    Return a tuple with cracked message, crossponding key and score.
    """
    cipher_bytes = decode_hex(cipher_hex)
    best_score_msg, best_key, max_score = '', '', 0

    for candidate_key in string.printable:
        # Use 'iso-8859-1'/'latin-1' codec to avoid UnicodeDecodeError 
        # as utf-8 being multibyte encoding doesnot define code points 
        # for bytes with MSB bit '1' (i.e. 128-255)
        plain_text = single_byte_xor(cipher_bytes, candidate_key.encode('utf-8'))\
            .decode('iso-8859-1')

        score = text_score(plain_text)
        if(score >= max_score):
            best_score_msg, best_key, max_score =  plain_text, candidate_key, score
    
    return best_score_msg, best_key, max_score

assert test_output == crack_single_byte_xor_cipher(hex_string)[0], 'Test Failed!'

if __name__ == '__main__':
    if(len(sys.argv) == 2):
        cipher_hex = sys.argv[1]
        cracked = crack_single_byte_xor_cipher(cipher_hex)
        print(f'For key: {cracked[1]}, Plain text: {cracked[0]}')
    else:
        print(f'Usage: {sys.argv[0]} <hex_string>')

