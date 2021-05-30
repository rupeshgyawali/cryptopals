"""

Challenge 2:

Fixed XOR
---------
Write a function that takes two equal-length buffers and produces their XOR combination.

If your function works properly, then when you feed it the string:

1c0111001f010100061a024b53535009181c
... after hex decoding, and when XOR'd against:

686974207468652062756c6c277320657965
... should produce:

746865206b696420646f6e277420706c6179

"""

import sys

buffer_one = '1c0111001f010100061a024b53535009181c'
buffer_two = '686974207468652062756c6c277320657965'
test_output = '746865206b696420646f6e277420706c6179'

def fixed_xor(buffer_one: str, buffer_two: str) -> str:
    x1 = int(buffer_one, 16)
    x2 = int(buffer_two, 16)

    return hex(x1 ^ x2)[2:]

assert test_output == fixed_xor(buffer_one, buffer_two), 'Test Failed!'

if __name__ == '__main__':
    if(len(sys.argv) == 3):
        print(f"Fixed XORed: {fixed_xor(sys.argv[1], sys.argv[2])}")
    else:
        print(f"Usage: {sys.argv[0]} <buffer_one> <buffer_two>")

