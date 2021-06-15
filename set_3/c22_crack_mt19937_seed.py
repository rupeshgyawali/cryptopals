"""

Challenge 22:

Crack an MT19937 seed
-----------------------
https://cryptopals.com/sets/3/challenges/22
"""
import time
import random

from set_3.c21_mt19937_rng import MT19937RNG

def get_random_number() -> int:
    # Wait a random number of seconds between, say, 40 and 1000
    # time.sleep(random.randint(40, 1000))
    global current_timestamp
    current_timestamp = int(time.time()) + random.randint(40, 1000) # simulating passage of time
    
    mersenne_twister = MT19937RNG()
    
    # Seed the rng with the current unix timestamp
    # seed = int(time.time())
    seed = current_timestamp
    
    mersenne_twister.seed_mt(seed)
    
    # Wait a random number of seconds again
    # time.sleep(random.randint(40, 1000))
    current_timestamp += random.randint(40, 1000) # simulating passage of time

    return mersenne_twister.extract_number()

def crack_seed(random_number: int) -> int:
    # current_timestamp = int(time.time())
    global current_timestamp
    cracked_seed = current_timestamp

    while True:
        rng = MT19937RNG()
        rng.seed_mt(cracked_seed)
        if rng.extract_number() == random_number:
            break
        cracked_seed -= 1

    return cracked_seed

if __name__ == '__main__':
    random_number = get_random_number()
    print(f'First RNG output: {random_number}')

    cracked_seed = crack_seed(random_number)
    print(f'Cracked seed: {cracked_seed}')

    rng = MT19937RNG()
    rng.seed_mt(cracked_seed)
    assert random_number == rng.extract_number(), "Test Failed!"
