"""

Challenge 9:

Implement PKCS#7 padding
------------------------
A block cipher transforms a fixed-sized block (usually 8 or 16 bytes) of plaintext into ciphertext. But we almost never want to transform a single block; we encrypt irregularly-sized messages.

One way we account for irregularly-sized messages is by padding, creating a plaintext that is an even multiple of the blocksize. The most popular padding scheme is called PKCS#7.

So: pad any block to a specific block length, by appending the number of bytes of padding to the end of the block. For instance,

"YELLOW SUBMARINE"
... padded to 20 bytes would be:

"YELLOW SUBMARINE\x04\x04\x04\x04"

"""

message = b'YELLOW SUBMARINE'
padded_message = b'YELLOW SUBMARINE\x04\x04\x04\x04'
block_size = 20

def PKCS7_pad(message: bytes, block_size: int) -> bytes:
    padding_length = block_size - (len(message) % block_size)
    padding_bytes = bytes([padding_length]) * padding_length
    
    padded_message = message + padding_bytes
    return padded_message

def PKCS7_unpad(message: bytes) -> bytes:
    padding_length = message[-1]
    if message[-padding_length:] != bytes([padding_length])*padding_length:
        raise ValueError('Invalid Padding')

    return message[:-padding_length]

assert padded_message == PKCS7_pad(message, block_size), 'Padding Failed!'
assert message == PKCS7_unpad(padded_message), 'Unpadding Failed!'

if __name__ == '__main__':
    padded_message = PKCS7_pad(message, block_size)

    print(padded_message)