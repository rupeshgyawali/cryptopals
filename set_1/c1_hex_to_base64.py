"""

Challenge 1:

Convert hex to base64
---------------------
The string:

49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d
Should produce:

SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t
So go ahead and make that happen. You'll need to use this code for the rest of the exercises.

Cryptopals Rule
Always operate on raw bytes, never on encoded strings. Only use hex and base64 for pretty-printing.

"""

import sys
import base64

hex_string = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
test_string = 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'

def hex_to_base64(hex_string: str) -> str:
    x = int(hex_string, 16)
    data_bytes =  x.to_bytes((x.bit_length() + 7)//8, byteorder='big')
    return base64.b64encode(data_bytes).decode('utf-8')

assert test_string == hex_to_base64(hex_string), 'Test Failed!'

if __name__ == "__main__":
    if(len(sys.argv) == 2):
        print(f"Base64 encoded: {hex_to_base64(sys.argv[1])}")
    else:
        print(f"Usage: {sys.argv[0]} <hex_string>")

