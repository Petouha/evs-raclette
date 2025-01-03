import math

def int_to_bytes(n):
    """Converts int to bytes."""
    return n.to_bytes((n.bit_length() + 7) // 8, 'big')


def mod_inv(a, n):
    t, r = 1, a
    new_t, new_r = 0, n

    while new_r != 0:
        quotient = r // new_r
        t, new_t = new_t, t - quotient * new_t
        r, new_r = new_r, r - quotient * new_r

    if r > 1:
        raise Exception("a is not invertible")
    if t < 0:
        t = t + n
    return t

def mod_sqrt(a, p):
    """
    Compute the modular square root of a modulo p.
    Finds x such that x^2 ≡ a (mod p).

    Parameters:
    a (int): The number for which the square root is computed.
    p (int): The prime modulus.

    Returns:
    int: A solution x such that x^2 ≡ a (mod p), or None if no solution exists.
    """
    # Check if the solution exists using Euler's criterion
    if pow(a, (p - 1) // 2, p) != 1:
        return None  # No solution exists

    # Special case for p ≡ 3 (mod 4), allows direct computation
    if p % 4 == 3:
        return pow(a, (p + 1) // 4, p)

    # General case using Tonelli-Shanks algorithm
    # Find a non-residue z
    z = 2
    while pow(z, (p - 1) // 2, p) == 1:
        z += 1

    q, s = p - 1, 0
    while q % 2 == 0:
        q //= 2
        s += 1

    m = s
    c = pow(z, q, p)
    t = pow(a, q, p)
    r = pow(a, (q + 1) // 2, p)

    while t != 0 and t != 1:
        t2 = t
        i = 0
        for i in range(1, m):
            t2 = pow(t2, 2, p)
            if t2 == 1:
                break
        b = pow(c, 1 << (m - i - 1), p)
        m = i
        c = pow(b, 2, p)
        t = (t * c) % p
        r = (r * b) % p

    return r if t == 1 else None
