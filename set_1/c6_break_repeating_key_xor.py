"""

Challenge 6:

Break repeating-key XOR
-----------------------
It is officially on, now.
This challenge isn't conceptually hard, but it involves actual error-prone coding. The other challenges in this set are there to bring you up to speed. This one is there to qualify you. If you can do this one, you're probably just fine up to Set 6.

There's a file here. It's been base64'd after being encrypted with repeating-key XOR.

Decrypt it.

Here's how:

Let KEYSIZE be the guessed length of the key; try values from 2 to (say) 40.
Write a function to compute the edit distance/Hamming distance between two strings. The Hamming distance is just the number of differing bits. The distance between:
this is a test
and
wokka wokka!!!
is 37. Make sure your code agrees before you proceed.
For each KEYSIZE, take the first KEYSIZE worth of bytes, and the second KEYSIZE worth of bytes, and find the edit distance between them. Normalize this result by dividing by KEYSIZE.
The KEYSIZE with the smallest normalized edit distance is probably the key. You could proceed perhaps with the smallest 2-3 KEYSIZE values. Or take 4 KEYSIZE blocks instead of 2 and average the distances.
Now that you probably know the KEYSIZE: break the ciphertext into blocks of KEYSIZE length.
Now transpose the blocks: make a block that is the first byte of every block, and a block that is the second byte of every block, and so on.
Solve each block as if it was single-character XOR. You already have code to do this.
For each block, the single-byte XOR key that produces the best looking histogram is the repeating-key XOR key byte for that block. Put them together and you have the key.

This code is going to turn out to be surprisingly useful later on. Breaking repeating-key XOR ("Vigenere") statistically is obviously an academic exercise, a "Crypto 101" thing. But more people "know how" to break it than can actually break it, and a similar technique breaks something much more important.

No, that's not a mistake.
We get more tech support questions for this challenge than any of the other ones. We promise, there aren't any blatant errors in this text. In particular: the "wokka wokka!!!" edit distance really is 37.

"""

import base64
from typing import Union, Tuple

import c3_single_byte_xor_cipher as c3
import c5_repeating_key_xor as c5

def hamming_distance(s_one: Union[bytes, str], s_two: Union[bytes, str]) -> int:
    bytes_one = bytes(s_one, 'ascii') if type(s_one) is str else s_one 
    bytes_two = bytes(s_two, 'ascii') if type(s_two) is str else s_two
    xor_bytes = bytes()
    for i, j in zip(bytes_one, bytes_two):
        xor_bytes += bytes([i ^ j])

    h_distance = 0
    x = int.from_bytes(xor_bytes, 'big')
    # count number of 1's
    while x:
        h_distance += x & 1
        x >>= 1

    return h_distance

def get_cipher_text_from_file(file_name: str) -> bytes:
    with open(file_name, 'r') as f:
        cipher_b64 = f.read()
    cipher_text = base64.b64decode(cipher_b64)

    return cipher_text

def guess_key_size(cipher_text: bytes) -> int:
    smallest_normalized_h_distance = 8
    guessed_key_size = 2
    for key_size in range(2, 40):
        s = 0
        no_of_blocks = len(cipher_text)//key_size
        for i in range(no_of_blocks):
            block_one = cipher_text[i*key_size:key_size*(i+1)]
            block_two = cipher_text[key_size*(i+1):key_size*(i+2)]
            normalized_h_distance = hamming_distance(block_one, block_two)/key_size
            s += normalized_h_distance
        
        avg = s/no_of_blocks
        if smallest_normalized_h_distance > avg:
            smallest_normalized_h_distance = avg
            guessed_key_size = key_size

    return guessed_key_size

def crack_repeating_key_xor(cipher_text: bytes) -> Tuple[str, str]:
    """
    Returns a tuple with cracked key and message.
    """
    key_size = guess_key_size(cipher_text)
    key = ''
    for i in range(key_size):
        ith_block = bytes([cipher_text[k] for k in range(i, len(cipher_text), key_size)])
        key += c3.crack_single_byte_xor_cipher(ith_block.hex())[1]
    
    return key, c5.repeating_key_xor(cipher_text.decode(), key).decode()

assert hamming_distance('this is a test', 'wokka wokka!!!') == 37, 'Hamming distance failed!'

if __name__ == '__main__':
    cipher_text = get_cipher_text_from_file('set_1/6.txt')
    key, message = crack_repeating_key_xor(cipher_text)
    print(f'Key: {key}')
    assert key == 'Terminator X: Bring the noise'
    print(f'Message: {message}')

