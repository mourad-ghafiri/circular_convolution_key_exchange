import random
import secrets
import time

def fast_pow_mod(base, exponent, modulus):
    """
    Efficiently compute (base^exponent) % modulus using square-and-multiply algorithm.
    
    Args:
        base (int): Base value
        exponent (int): Exponent
        modulus (int): Modulus
    
    Returns:
        int: (base^exponent) % modulus
    """
    if modulus == 1:
        return 0
    
    result = 1
    base = base % modulus
    
    while exponent > 0:
        # If exponent is odd, multiply the result with base
        if exponent & 1:
            result = (result * base) % modulus
        
        # Square the base and reduce exponent by half
        exponent >>= 1
        base = (base * base) % modulus
    
    return result

def is_prime(n, k=40):
    """
    Miller-Rabin primality test.
    
    Args:
        n (int): Number to test for primality
        k (int): Number of test rounds (higher k increases accuracy)
    
    Returns:
        bool: True if n is probably prime, False if definitely composite
    """
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0:
        return False
    
    # Express n-1 as 2^r * d where d is odd
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    
    # Witness loop
    for _ in range(k):
        a = random.randint(2, n - 2)
        x = fast_pow_mod(a, d, n)
        
        if x == 1 or x == n - 1:
            continue
        
        for _ in range(r - 1):
            x = fast_pow_mod(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    
    return True

def find_prime_congruent(bits, n):
    """
    Find a prime number p of specified bit length where p-1 is divisible by n.
    
    Args:
        bits (int): Desired bit length of the prime
        n (int): Value that should divide p-1
    
    Returns:
        int: A prime number p of the specified bit length where p-1 is divisible by n
    """
    while True:
        # Generate a random number of specified bit length
        k = secrets.randbits(bits - 1)
        # Ensure p-1 is divisible by n by setting p = k*n + 1
        p = k * n + 1
        
        # Make sure p has exactly 'bits' bits
        if p.bit_length() != bits:
            continue
            
        if is_prime(p):
            return p

def find_primitive_root(p, n):
    """
    Find a primitive n-th root of unity modulo p.
    
    Args:
        p (int): Prime modulus
        n (int): Sequence length (must divide p-1)
    
    Returns:
        int: Primitive n-th root of unity
    """
    if (p - 1) % n != 0:
        raise ValueError(f"n={n} does not divide p-1={p-1}")
    
    # Find a generator g of the multiplicative group
    g = 2
    max_attempts = 100  # Avoid infinite loops
    attempts = 0
    
    while attempts < max_attempts:
        # Check if g is a generator of the multiplicative group
        if fast_pow_mod(g, (p - 1) // 2, p) != 1:
            break
        g += 1
        attempts += 1
    
    if attempts == max_attempts:
        raise ValueError("Failed to find a generator of the multiplicative group")
    
    # Compute w = g^((p-1)/n) mod p
    w = fast_pow_mod(g, (p - 1) // n, p)
    
    # Verify w is a primitive n-th root of unity
    if fast_pow_mod(w, n, p) != 1:
        raise ValueError("Failed to find primitive n-th root of unity")
    
    return w

def ntt(A, w, p):
    """
    Iterative implementation of Number Theoretic Transform (more stable than recursive).
    
    Args:
        A (list): Input sequence
        w (int): Primitive n-th root of unity
        p (int): Prime modulus
    
    Returns:
        list: NTT of A
    """
    n = len(A)
    if n == 1:
        return A.copy()
    
    # Check if n is a power of 2
    if n & (n - 1) != 0:
        raise ValueError("NTT length must be a power of 2")
    
    # Make a copy to avoid modifying the input
    A_copy = A.copy()
    
    # Bit-reverse permutation
    j = 0
    for i in range(1, n):
        bit = n >> 1
        while j >= bit:
            j -= bit
            bit >>= 1
        j += bit
        
        if i < j:
            A_copy[i], A_copy[j] = A_copy[j], A_copy[i]
    
    # Cooley-Tukey iterative FFT
    for s in range(1, n.bit_length()):
        m = 1 << s  # 2^s
        w_m = fast_pow_mod(w, (p - 1) // m, p)
        
        for k in range(0, n, m):
            omega = 1
            for j in range(m // 2):
                t = (omega * A_copy[k + j + m // 2]) % p
                u = A_copy[k + j]
                A_copy[k + j] = (u + t) % p
                A_copy[k + j + m // 2] = (u - t) % p
                omega = (omega * w_m) % p
    
    return A_copy

def intt(B, w, p):
    """
    Inverse Number Theoretic Transform.
    
    Args:
        B (list): Input sequence in frequency domain
        w (int): Primitive n-th root of unity
        p (int): Prime modulus
    
    Returns:
        list: Inverse NTT of B
    """
    n = len(B)
    
    # Compute the inverse of w
    w_inv = fast_pow_mod(w, p - 2, p)
    
    # Compute the inverse of n
    n_inv = fast_pow_mod(n, p - 2, p)
    
    # Compute INTT using NTT with inverse root
    result = ntt(B, w_inv, p)
    
    # Scale by 1/n
    for i in range(n):
        result[i] = (result[i] * n_inv) % p
    
    return result

def convolve_power(G, a, w, p):
    """
    Compute G^{*a}, the sequence G convolved with itself a times.
    
    Args:
        G (list): Base sequence
        a (int): Exponent (number of convolutions)
        w (int): Primitive n-th root of unity
        p (int): Prime modulus
    
    Returns:
        list: Result of G^{*a}
    """
    F_G = ntt(G, w, p)            # Transform G to frequency domain
    F_Ga = [fast_pow_mod(f, a, p) for f in F_G]  # Pointwise exponentiation
    Ga = intt(F_Ga, w, p)         # Transform back to time domain
    return Ga

def generate_random_sequence(length, prime):
    """
    Generate a random sequence of specified length with elements in GF(p).
    
    Args:
        length (int): Length of the sequence
        prime (int): Prime modulus
    
    Returns:
        list: Random sequence
    """
    return [random.randint(1, prime-1) for _ in range(length)]

def main():
    print("NTT-Based Key Exchange Protocol with Large Numbers")
    print("="*50)
    
    # Set parameters for cryptographic security
    bits = 2048  # Reduced for demonstration; use 2048+ bits for real security
    n = 16      # Sequence length (must be a power of 2 for efficient NTT)
    
    print(f"\nGenerating a {bits}-bit prime where p-1 is divisible by {n}...")
    start_time = time.time()
    
    # Generate a prime p where p-1 is divisible by n
    p = find_prime_congruent(bits, n)
    print(f"Prime p = {p}")
    print(f"Verifying (p-1) % n == 0: {(p-1) % n == 0}")
    print(f"Time: {time.time() - start_time:.2f} seconds")
    
    print(f"\nFinding primitive {n}-th root of unity...")
    start_time = time.time()
    try:
        w = find_primitive_root(p, n)
        print(f"w = {w}")
        print(f"Verifying w^n ≡ 1 (mod p): {fast_pow_mod(w, n, p) == 1}")
        print(f"Time: {time.time() - start_time:.2f} seconds")
    except ValueError as e:
        print(f"Error: {e}")
        return
    
    # Generate a random public sequence G
    print("\nGenerating random public sequence G...")
    G = generate_random_sequence(n, p)
    print(f"G = {G}")
    
    # Alice's part
    print("\nAlice's actions:")
    a = secrets.randbelow(p - 1) + 1  # Alice's secret key, ensuring a > 0
    print(f"Alice's secret key a = {a}")
    
    start_time = time.time()
    Ga = convolve_power(G, a, w, p)
    print(f"Time to compute G^{{*a}}: {time.time() - start_time:.2f} seconds")
    print(f"Alice sends G^{{*a}} = {Ga}")
    
    # Bob's part
    print("\nBob's actions:")
    b = secrets.randbelow(p - 1) + 1  # Bob's secret key, ensuring b > 0
    print(f"Bob's secret key b = {b}")
    
    start_time = time.time()
    Gb = convolve_power(G, b, w, p)
    print(f"Time to compute G^{{*b}}: {time.time() - start_time:.2f} seconds")
    print(f"Bob sends G^{{*b}} = {Gb}")
    
    # Alice computes the shared key
    print("\nShared key computation:")
    start_time = time.time()
    K_alice = convolve_power(Gb, a, w, p)
    print(f"Time for Alice to compute shared key: {time.time() - start_time:.2f} seconds")
    
    # Bob computes the shared key
    start_time = time.time()
    K_bob = convolve_power(Ga, b, w, p)
    print(f"Time for Bob to compute shared key: {time.time() - start_time:.2f} seconds")
    
    # Verify that Alice and Bob derived the same key
    if K_alice == K_bob:
        print("\nSuccess: Alice and Bob have derived the same shared key!")
        print(f"Shared key = {K_alice}")
    else:
        print("\nError: Shared keys do not match")
        print(f"Alice's key: {K_alice}")
        print(f"Bob's key: {K_bob}")
    
    # Optional verification: compute G^{* (a*b)} directly
    print("\nVerification:")
    start_time = time.time()
    ab = (a * b)  # We don't need modulo (p-1) here
    K_direct = convolve_power(G, ab, w, p)
    print(f"Time to compute G^{{*ab}} directly: {time.time() - start_time:.2f} seconds")
    
    if K_alice == K_direct:
        print("Verification passed: K_alice matches G^{*(a*b)}")
    else:
        print("Verification failed: K_alice does not match G^{*(a*b)}")
        # Print first few elements for comparison
        print(f"First few elements of K_alice: {K_alice[:3]}")
        print(f"First few elements of K_direct: {K_direct[:3]}")

if __name__ == "__main__":
    main() 
