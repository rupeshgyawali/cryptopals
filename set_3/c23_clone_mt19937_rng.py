"""

Challenge 23:

Clone an MT19937 RNG from its output
-----------------------
https://cryptopals.com/sets/3/challenges/23
"""
from typing import List

from set_3.c21_mt19937_rng import MT19937RNG

def get_batch_output(mt_rng: MT19937RNG) -> List[int]:
    return [mt_rng.extract_number() for _ in range(MT19937RNG.N)]

def get_mt_state_from_batch_output(batch_output: List[int]) -> List[int]:
    return [untemper(random_number) for random_number in batch_output]

def untemper(random_number: int) -> int:
    """
    Reverse the tampering operation of Mersenne Twister to recover
    its state from random number.
    """
    y = random_number

    # Reverse: y = y ^ (y >> MT19937RNG.L)
    y = reverse_right(y, MT19937RNG.L, 0xffffffff)
    # Reverse: y = y ^ ((y << MT19937RNG.T) & MT19937RNG.C)
    y = reverse_left(y, MT19937RNG.T, MT19937RNG.C)
    # Reverse: y = y ^ ((y << MT19937RNG.S) & MT19937RNG.B)
    y = reverse_left(y, MT19937RNG.S, MT19937RNG.B)
    # Reverse: y = y ^ ((y >> MT19937RNG.U) & MT19937RNG.D)
    y = reverse_right(y, MT19937RNG.U, MT19937RNG.D)

    return y
        
def reverse_right(y: int, shift: int, magic_number: int) -> int:
    """
    Reverse the right shift operation.
    
    For unknown ym1 in: y = ym1 ^ ((ym1 >> shift) & magic_number) 
    Returns: ym1 = ?
    """
    ym1 = 0
    # Divide the number's bits into blocks of length equal to shift
    # Counting the blocks from msb to lsb
    for i in range(MT19937RNG.W//shift):
        y_ith_block = (y >> (MT19937RNG.W - (i+1)*shift)) & (2 ** shift - 1)
        magic_number_ith_block = (magic_number >> (MT19937RNG.W - (i+1)*shift)) & (2 ** shift - 1)
        ym1_ith_block = y_ith_block ^ (ym1 & magic_number_ith_block)
        ym1 = (ym1 << shift) ^ ym1_ith_block

    remaining_bits = MT19937RNG.W % shift
    if remaining_bits:
        y_remaining = y & (2 ** remaining_bits - 1)
        magic_number_remaining = magic_number & (2 ** remaining_bits - 1)
        ym1_remaining = y_remaining ^ ((ym1 >> (shift - remaining_bits)) & magic_number_remaining)
        ym1 = (ym1 << remaining_bits) ^ ym1_remaining

    return ym1

def reverse_left(y: int, shift: int, magic_number: int) -> int:
    """
    Reverse the left shift operation.

    For unknown ym1 in: y = ym1 ^ ((ym1 << shift) & magic_number)
    Returns: ym1 = ?
    """
    ym1 = 0
    # Divide the number's bits into blocks of length equal to shift
    # Counting the blocks from lsb to msb
    for i in range(MT19937RNG.W//shift):
        y_ith_block = (y >> i*shift) & (2 ** shift - 1)
        magic_number_ith_block = (magic_number >> i*shift) & (2 ** shift - 1)
        ym1_i_minus_1th_block = ((ym1 >> (i-1)*shift) & (2 ** shift - 1)) if i > 0 else ym1
        ym1_ith_block = y_ith_block ^ (ym1_i_minus_1th_block & magic_number_ith_block)
        ym1 = (ym1_ith_block << i * shift) ^ ym1
    
    remaining_bits = MT19937RNG.W % shift
    if remaining_bits:
        y_remaining = (y >> (MT19937RNG.W - remaining_bits)) & (2 ** remaining_bits - 1)
        magic_number_remaining = (magic_number >> (MT19937RNG.W - remaining_bits)) & (2 ** remaining_bits - 1)
        ym1_remaining = y_remaining ^ (((ym1 >> (MT19937RNG.W - remaining_bits - shift)) & (2 ** remaining_bits - 1)) & magic_number_remaining)
        ym1 = (ym1_remaining << (MT19937RNG.W - remaining_bits)) ^ ym1
    
    return ym1

def clone_rng_from_state(state: List[int]) -> MT19937RNG:
    cloned_mt_rng = MT19937RNG()
    
    cloned_mt_rng._MT = list(state)
    cloned_mt_rng._index = MT19937RNG.N

    return cloned_mt_rng

if __name__ == '__main__':
    mt_rng = MT19937RNG()
    batch_output = get_batch_output(mt_rng)

    state = get_mt_state_from_batch_output(batch_output)

    cloned_mt_rng = clone_rng_from_state(state)

    for i in range(10):
        random_number = mt_rng.extract_number()
        cloned_random_number = cloned_mt_rng.extract_number()
        assert(random_number == cloned_random_number)
        print(f'Random: {random_number}; Cloned: {cloned_random_number}')
