"""

Challenge 15:

PKCS#7 padding validation
--------------------------------------
https://cryptopals.com/sets/2/challenges/15

"""

import c9_pkcs7_padding as c9

if __name__ == '__main__':
    for msg in [b'ICE ICE BABY\x04\x04\x04\x04', b'ICE ICE BABY\x05\x05\x05\x05', b'ICE ICE BABY\x01\x02\x03\x04']:
        try:
            c9.PKCS7_unpad(msg)
            print(f'{msg} --> Valid')
        except ValueError:
            print(f'{msg} --> Invalid')
            
    # print(c9.PKCS7_unpad(b'ICE ICE BABY\x04\x04\x04\x04'))
    # print(c9.PKCS7_unpad(b'ICE ICE BABY\x05\x05\x05\x05'))
    # print(c9.PKCS7_unpad(b'ICE ICE BABY\x01\x02\x03\x04'))

