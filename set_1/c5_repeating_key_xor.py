"""

Challenge 5:

Implement repeating-key XOR
----------------------------
Here is the opening stanza of an important work of the English language:

Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal
Encrypt it, under the key "ICE", using repeating-key XOR.

In repeating-key XOR, you'll sequentially apply each byte of the key; the first byte of plaintext will be XOR'd against I, the next C, the next E, then I again for the 4th byte, and so on.

It should come out to:

0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272
a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f
Encrypt a bunch of stuff using your repeating-key XOR function. Encrypt your mail. Encrypt your password file. Your .sig file. Get a feel for it. I promise, we aren't wasting your time with this.

"""

from argparse import ArgumentParser

message = '''Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal'''
key = 'ICE'
test_output = '0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272'\
    'a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f'

def byte_xor(byte_one: bytes, byte_two: bytes) -> bytes:
    x1 = int.from_bytes(byte_one, 'big')
    x2 = int.from_bytes(byte_two, 'big')
    y = x1 ^ x2
    return bytes([y])

def repeating_key_xor(message: str, key: str) -> bytes:
    key_length = len(key)
    message_xor = bytes()
    for i, char in enumerate(message):
        char_xor = byte_xor(bytes([ord(char)]), bytes([ord(key[i%key_length])]))
        message_xor += char_xor
    
    return message_xor

def repeating_key_xor_file(file_name: str, key: str, output_file: str = None) -> None:
    """
    Encrypts the given file and outputs to output_file.
    """
    if output_file is None:
        output_file = f'{file_name}.rxor'
    
    key_length = len(key)
    with open(file_name, 'rb') as fr, open(output_file, 'wb') as fw:
        i = 0
        while True:
            b = fr.read(1)
            if not b:
                break
            b_xor = byte_xor(b, bytes([ord(key[i%key_length])]))
            fw.write(b_xor)
            i += 1

assert test_output == repeating_key_xor(message, key).hex(), 'Test Failed!'

if __name__ == '__main__':
    parser = ArgumentParser()
    parser.add_argument('-f', '--file', metavar='file_name', type=str, nargs=1, help='Encrypt/Decrypt given file')
    parser.add_argument('-o', '--output', metavar='output_file', type=str, nargs=1, help='File to output to')
    parser.add_argument('message', nargs='?')
    parser.add_argument('key', nargs=1)

    args = parser.parse_args()
    if args.file is not None:
        if args.output is not None:
            output = args.output[0]
        else:
            output = None
        repeating_key_xor_file(args.file[0], args.key[0], output)
    
    if args.message is not None:
        print(f'Cipher: {repeating_key_xor(args.message, args.key[0]).hex()}')
