"""

Challenge 17:

The CBC padding oracle
-----------------------
https://cryptopals.com/sets/3/challenges/17
"""
import os
import random
import base64

from utils.xor import xor
from utils.padding import PKCS7, PaddingError
from utils.aes import AES, Mode

STRING_CHOICES = [
            'MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=',
            'MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=',
            'MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==',
            'MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==',
            'MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl',
            'MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==',
            'MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==',
            'MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=',
            'MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=',
            'MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93',
        ]

class CBCPaddingOracle:
    def __init__(self) -> None:
        self._key = os.urandom(AES.KEY_SIZE)
        self._block_size = AES.BLOCK_SIZE
        self._cipher = AES(Mode.CBC)

    def select_and_encrypt(self) -> bytes:
        selected_string = random.choice(STRING_CHOICES)
        plaintext = base64.b64decode(selected_string)
        
        padded_plaintext = PKCS7.pad(plaintext, self._block_size)
        
        iv = os.urandom(self._block_size)
        ciphertext = self._cipher.encrypt(padded_plaintext, self._key, iv)

        return ciphertext, iv

    def decrypt_and_check(self, ciphertext: bytes, iv: bytes) -> bool:
        plaintext = self._cipher.decrypt(ciphertext, self._key, iv)
        try:
            unpadded_plaintext = PKCS7.unpad(plaintext)
        except PaddingError:
            return False

        return True

def padding_oracle_attack(padding_oracle: CBCPaddingOracle, ciphertext: bytes, iv: bytes, block_size: int) -> bytes:
    """
    Returns plaintext for the given ciphertext and iv from padding oracle.
    """
    no_of_blocks = len(ciphertext) // block_size
    plaintext = b''

    # We crack a block at a time. Each time we take two blocks; block to be cracked 
    # and previous block. For first block, previous block is IV
    previous_block = iv
    for i in range(no_of_blocks):
        # This is the current block to be cracked.
        current_block = ciphertext[i*block_size:(i+1)*block_size]

        # Currently cracked plain block; which is empty initially.
        plain_block = b''
        for j in range(block_size):
            # Cracking is done from last byte to first.
            current_byte_index = block_size - j - 1
            # Output of decryption before xor with previous cipher block; Only for those bytes 
            # that are already cracked.
            ecb_decrypted = xor(plain_block, previous_block[current_byte_index+1:])
            # For cracking each byte in a block, we take every possible byte flip in previous cipher block.
            for k in range(1, 256):
                # For each byte, take pervious cipher block bytes upto that byte, filp the byte. 
                # So there is identical byte filp in plaintext.
                previous_block_tampered = previous_block[:-(j+1)] + bytes([k])
                # All the remaining bytes for previous cipher block are flipped so that valid padding
                # would be produced.
                previous_block_tampered += xor(ecb_decrypted, bytes([j+1])*j)
                # Check if byte filps makes padding valid
                is_valid = padding_oracle.decrypt_and_check(current_block, previous_block_tampered)
                if is_valid:
                    # Slice object for obtaining current byte. We perform slicing instead of indexing
                    # because we donot want integer when the cipher block is indexed; we want single byte.
                    byte_index = slice(current_byte_index, current_byte_index+1)

                    ecb_decrypted_plain_byte = xor(bytes([j+1]), bytes([k]))
                    plain_byte = xor(ecb_decrypted_plain_byte, previous_block[byte_index])
                    # Since craking is done from last byte to first, cracked byte is added before
                    plain_block = plain_byte + plain_block
                    break

        plaintext += plain_block
        previous_block = current_block

    return plaintext



if __name__ == '__main__':
    padding_oracle = CBCPaddingOracle()
    
    # Test if the oracle functions are working correctly
    for i in range(15):
        ciphertext, iv = padding_oracle.select_and_encrypt()
        is_valid = padding_oracle.decrypt_and_check(ciphertext, iv)
        assert(is_valid == True)
    
    ciphertext, iv = padding_oracle.select_and_encrypt()
    block_size = AES.BLOCK_SIZE
    plaintext = padding_oracle_attack(padding_oracle, ciphertext, iv, block_size)
    
    print(plaintext)
    

