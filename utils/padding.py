class PaddingError(Exception):
    pass

class PKCS7:
    """Pad/Unpad messages using PKCS#7 padding scheme"""
    @staticmethod
    def pad(message: bytes, block_size: int) -> bytes:
        # if message is already multiple of block_size, padding 
        # equal to block_size is added.
        padding_length = block_size - (len(message) % block_size)
        padding_bytes = bytes([padding_length]) * padding_length
        
        padded_message = message + padding_bytes
        return padded_message

    @staticmethod
    def unpad(message: bytes) -> bytes:
        padding_length = message[-1]
        if message[-padding_length:] != bytes([padding_length])*padding_length:
            raise PaddingError('Bad padding')

        return message[:-padding_length]
