"""

Challenge 21:

Implement the MT19937 Mersenne Twister RNG
-----------------------
https://cryptopals.com/sets/3/challenges/21
"""

class MT19937RNG:
    """
    MT19937 (32-bit) Mersenne Twister Random Number Generator.

    Implements pseudocode from wikipedia.com
    """
    W, N, M, R = (32, 624, 397, 31)
    A = 0x9908B0DF
    U, D = (11, 0xFFFFFFFF)
    S, B = (7, 0x9D2C5680)
    T, C = (15, 0xEFC60000)
    L = 18
    F = 1812433253

    LOWER_W_BIT_MASK = 2 ** W - 1

    def __init__(self) -> None:
        # Create a length n array to store the state of the generator
        self._MT = [0 for _ in range(MT19937RNG.N)]
        self._index = MT19937RNG.N + 1
        self._LOWER_MASK = (1 << MT19937RNG.R) - 1 # That is, the binary number of r 1's
        # Lowest w bits of (not lower_mask)
        self._UPPER_MASK = ~self._LOWER_MASK & MT19937RNG.LOWER_W_BIT_MASK

    def seed_mt(self, seed: int) -> None:
        """Initializes the generator from a seed"""
        self._index = MT19937RNG.N
        self._MT[0] = seed
        for i in range(1, MT19937RNG.N): # loop over each element
            temp = MT19937RNG.F * (self._MT[i-1] ^ (self._MT[i-1] >> (MT19937RNG.W -2))) + i
            self._MT[i] = temp & MT19937RNG.LOWER_W_BIT_MASK

    def extract_number(self) -> int:
        """
        Returns next random number.

        Extracts a tempered value based on MT[index]
        calling twist() every n numbers
        """
        if self._index >= MT19937RNG.N:
            if self._index > MT19937RNG.N:
                # Generator was never seeded
                # Seeding with constant value; 5489 used in reference C code
                self.seed_mt(5489)
            self.twist()

        y = self._MT[self._index]
        y = y ^ ((y >> MT19937RNG.U) & MT19937RNG.D)
        y = y ^ ((y << MT19937RNG.S) & MT19937RNG.B)
        y = y ^ ((y << MT19937RNG.T) & MT19937RNG.C)
        y = y ^ (y >> MT19937RNG.L)

        self._index += 1
        return y & MT19937RNG.LOWER_W_BIT_MASK

    def twist(self) -> None:
        """Generates the next n values from the series x_i"""
        for i in range(MT19937RNG.N):
            x = (self._MT[i] & self._UPPER_MASK) + (self._MT[(i+1) % MT19937RNG.N] & self._LOWER_MASK)
            xA = x >> 1
            if (x % 2) != 0:
                xA = xA ^ MT19937RNG.A
            self._MT[i] = self._MT[(i+MT19937RNG.M) % MT19937RNG.N] ^ xA

        self._index = 0

if __name__ == '__main__':
    mersenne_twister = MT19937RNG()
    mersenne_twister.seed_mt(1624457671)
    for _ in range(10):
        random_number = mersenne_twister.extract_number()
        print(random_number)


