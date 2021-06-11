def xor(x: bytes, y: bytes) -> bytes:
    """Performs xor operation between x and y.
    
    If x and y are of unequal length, repeat the short one.
    """
    xored = bytes()
    x_len, y_len = len(x), len(y)
    for i in range(max(x_len, y_len)):
        xored += bytes([x[i%x_len] ^ y[i%y_len]])

    return xored