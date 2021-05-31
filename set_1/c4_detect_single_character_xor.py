"""

Challenge 4:

Detect single-character XOR
----------------------------
One of the 60-character strings in this file has been encrypted by single-character XOR.

Find it.

(Your code from #3 should help.)

"""

import sys
from typing import Tuple

import c3_single_byte_xor_cipher as c3

file_name = 'set_1/4.txt'
test_output = 'Now that the party is jumping\n'

def detect_single_byte_xor_from_file(file_name: str) -> Tuple[int, str, str, int]:
    """
    Returns a tuple with index of detected string, cracked message, key and score.
    """
    with open(file_name, 'r') as f:
        best_cracked, max_score, index = tuple(), 0, 0

        for i, line in enumerate(f):
            string = line[:-1] # removing newline character
            cracked = c3.crack_single_byte_xor_cipher(string)
            if(cracked[2] > max_score):
                best_cracked, max_score, index =  cracked, cracked[2], i
    
    return index, *best_cracked

assert test_output == detect_single_byte_xor_from_file(file_name)[1], 'Test Failed!'

if __name__ == '__main__':
    if(len(sys.argv) == 2):
        file_name = sys.argv[1]
        detected = detect_single_byte_xor_from_file(file_name)
        print(f'{detected[0]}th string; key: {detected[2]}; message: {detected[1]}')
    else:
        print(f'Usage: {sys.argv[0]} <file_name>')
