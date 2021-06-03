"""

Challenge 8:

Detect AES in ECB mode
-----------------------
In this file are a bunch of hex-encoded ciphertexts.

One of them has been encrypted with ECB.

Detect it.

Remember that the problem with ECB is that it is stateless and deterministic; the same 16 byte plaintext block will always produce the same 16 byte ciphertext.

"""

def no_of_repeated_blocks(cipher_text: bytes, block_size: int) -> int:
    no_of_blocks = len(cipher_text)//block_size
    blocks = [cipher_text[i*block_size:(i+1)*block_size] for i in range(no_of_blocks)]
    
    return no_of_blocks - len(set(blocks))

def detect_aes_ecb_mode(file_name: str) -> bytes:
    """
    Returns list of ecb encrypted cipher texts among all of the cipher texts in the given file.
    """
    with open(file_name, 'r') as f:
        ecb_detected_cipher_texts = []
        for cipher_text in f:
            n = no_of_repeated_blocks(bytes.fromhex(cipher_text.rstrip()), block_size=16)
            if n > 0:
                ecb_detected_cipher_texts.append(cipher_text.rstrip())
    
    return ecb_detected_cipher_texts

if __name__ == '__main__':
    print(detect_aes_ecb_mode('set_1/8.txt'))


