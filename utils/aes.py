from enum import Enum

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from utils.xor import xor

class Mode(Enum):
    """Encryption modes"""
    ECB = 1
    CBC = 2
    CTR = 3

class AES:
    """Encrypt/Decrypt messages using AES algorithm.
    
    Supported encryption modes: ECB, CBC, CTR
    Supported key size: 128 bits (16 bytes)
    """
    BLOCK_SIZE = 16
    KEY_SIZE = 16

    def __init__(self, mode: Mode) -> None:
        if isinstance(mode, Mode):
            self.mode = mode
        else:
           raise ValueError(f'Unsupported/Invalid mode {self.mode}') 

    def encrypt(self, plaintext: bytes, key: bytes, iv: bytes = None, nonce: bytes = None) -> bytes:
        if len(plaintext) % AES.BLOCK_SIZE != 0 and self.mode != Mode.CTR:
            raise ValueError(f'The plaintext must be of length multiple of '
                                f'block size ({AES.BLOCK_SIZE} bytes).')
        if len(key) != AES.KEY_SIZE:
            raise ValueError(f'The key must be exact {AES.KEY_SIZE} bytes long')

        if self.mode == Mode.ECB:
            ciphertext =  self._encrypt_ecb(plaintext, key)
        elif self.mode == Mode.CBC:
            ciphertext =  self._encrypt_cbc(plaintext, key, iv)
        elif self.mode == Mode.CTR:
            ciphertext = self._encrypt_decrypt_ctr(plaintext, key, nonce)
        else:
            raise ValueError(f'Unsupported/Invalid mode {self.mode}')

        return ciphertext

    def decrypt(self, ciphertext: bytes, key: bytes, iv: bytes = None, nonce: bytes= None) -> bytes:
        if len(ciphertext) % AES.BLOCK_SIZE != 0 and self.mode != Mode.CTR:
            raise ValueError(f'The ciphertext must be of length multiple of '
                                f'block size ({AES.BLOCK_SIZE} bytes).')
        if len(key) != AES.KEY_SIZE:
            raise ValueError(f'The key must be exact {AES.KEY_SIZE} bytes long')

        if self.mode == Mode.ECB:
            plaintext =  self._decrypt_ecb(ciphertext, key)
        elif self.mode == Mode.CBC:
            plaintext =  self._decrypt_cbc(ciphertext, key, iv)
        elif self.mode == Mode.CTR:
            plaintext = self._encrypt_decrypt_ctr(ciphertext, key, nonce)
        else:
            raise ValueError(f'Unsupported/Invalid mode {self.mode}')

        return plaintext


    def _encrypt_ecb(self, plaintext: bytes, key: bytes) -> bytes:
        backend = default_backend()
        cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
        encryptor = cipher.encryptor()

        return encryptor.update(plaintext) + encryptor.finalize()

    def _decrypt_ecb(self, ciphertext: bytes, key: bytes) -> bytes:
        backend = default_backend()
        cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
        decryptor = cipher.decryptor()

        return decryptor.update(ciphertext) + decryptor.finalize()

    def _encrypt_cbc(self, plaintext: bytes, key: bytes, iv: bytes = None) -> bytes:
        if iv is None:
            iv = bytes(AES.BLOCK_SIZE)
        
        ciphertext = bytes()
        previous_cipher_block = iv
        no_of_blocks = len(plaintext)//AES.BLOCK_SIZE
        for i in range(no_of_blocks):
            current_block = plaintext[i*AES.BLOCK_SIZE:(i+1)*AES.BLOCK_SIZE]
            addition_block = xor(current_block, previous_cipher_block)
            cipher_block = self._encrypt_ecb(addition_block, key)
            previous_cipher_block = cipher_block
            ciphertext += cipher_block
        
        return ciphertext

    def _decrypt_cbc(self, ciphertext: bytes, key: bytes, iv: bytes = None) -> bytes:
        if iv is None:
            iv = bytes(AES.BLOCK_SIZE)
        
        plaintext = bytes()
        previous_block = iv
        no_of_blocks = len(ciphertext)//AES.BLOCK_SIZE
        for i in range(no_of_blocks):
            current_block = ciphertext[i*AES.BLOCK_SIZE:(i+1)*AES.BLOCK_SIZE]
            ecb_plaintext = self._decrypt_ecb(current_block, key)
            plaintext += xor(ecb_plaintext, previous_block)
            previous_block = current_block
        
        return plaintext
    
    def _encrypt_decrypt_ctr(self, text: bytes, key: bytes, nonce: bytes = None) -> bytes:
        if nonce is None:
            nonce = bytes(8)
        if len(nonce) != 8:
            raise ValueError(f'The nonce must be 8 bytes long')
        
        plaintext_length = len(text)
        ciphertext = b''
        for bytecount in range(0, plaintext_length, AES.BLOCK_SIZE):
            block_count = bytecount // AES.BLOCK_SIZE
            counter = nonce + block_count.to_bytes(64//8, 'little')
            keystream = self._encrypt_ecb(counter, key)

            for plaintext_byte, keystream_byte in \
                        zip(text[bytecount:bytecount+AES.BLOCK_SIZE], keystream):
                ciphertext += bytes([plaintext_byte ^ keystream_byte])

        return ciphertext
