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

# New functions for public key cryptography

def generate_keys(G, a, w, p):
    """
    Generate a key pair for NTT-based public key cryptography.
    
    Args:
        G (list): Public sequence
        a (int): Private key (random integer)
        w (int): Primitive n-th root of unity
        p (int): Prime modulus
    
    Returns:
        tuple: (private_key, public_key)
               where private_key is integer a,
               and public_key is the pair (G, A) with A = G^{*a}
    """
    A = convolve_power(G, a, w, p)
    return a, (G, A)

def encrypt_message(message, public_key, w, p):
    """
    Encrypt a message using NTT-based public key cryptography.
    
    Args:
        message (list): Message as a sequence of integers in GF(p)
        public_key (tuple): Public key (G, A) where G is the public sequence and A = G^{*a}
        w (int): Primitive n-th root of unity
        p (int): Prime modulus
    
    Returns:
        tuple: Ciphertext as a pair (C1, C2)
    """
    G, A = public_key
    n = len(G)
    
    # Ensure message has the same length as G
    if len(message) != n:
        raise ValueError(f"Message length must be {n}")
    
    # Generate random r
    r = secrets.randbelow(p - 1) + 1  # Ensure r > 0
    
    # Compute C1 = G^{*r}
    C1 = convolve_power(G, r, w, p)
    
    # Compute A^{*r}
    A_r = convolve_power(A, r, w, p)
    
    # Compute C2 = M ⊕ A^{*r} (element-wise addition modulo p)
    C2 = [(message[i] + A_r[i]) % p for i in range(n)]
    
    return (C1, C2)

def decrypt_message(ciphertext, private_key, w, p):
    """
    Decrypt a ciphertext using NTT-based public key cryptography.
    
    Args:
        ciphertext (tuple): Ciphertext as a pair (C1, C2)
        private_key (int): Private key 'a'
        w (int): Primitive n-th root of unity
        p (int): Prime modulus
    
    Returns:
        list: Decrypted message
    """
    C1, C2 = ciphertext
    a = private_key
    
    # Compute S = C1^{*a}
    S = convolve_power(C1, a, w, p)
    
    # Recover M = C2 ⊖ S (element-wise subtraction modulo p)
    M = [(C2[i] - S[i]) % p for i in range(len(C2))]
    
    return M

def encode_text_to_sequences(text, n, p):
    """
    Encode text to multiple sequences of integers modulo p, handling text of any length.
    
    Args:
        text (str): Text to encode
        n (int): Length of each sequence
        p (int): Prime modulus
    
    Returns:
        list: List of encoded sequences
    """
    # Convert text to bytes
    bytes_data = text.encode('utf-8')
    
    # Calculate how many blocks we need
    num_blocks = (len(bytes_data) + n - 1) // n
    
    # Create blocks
    sequences = []
    for block in range(num_blocks):
        sequence = [0] * n
        for i in range(n):
            idx = block * n + i
            if idx < len(bytes_data):
                sequence[i] = bytes_data[idx] % p
        sequences.append(sequence)
    
    return sequences

def decrypt_and_decode_sequences(sequences, private_key, w, p):
    """
    Decrypt multiple ciphertexts and decode them back to text.
    
    Args:
        sequences (list): List of ciphertext pairs (C1, C2)
        private_key (int): Private key
        w (int): Primitive n-th root of unity
        p (int): Prime modulus
    
    Returns:
        str: Decoded text
    """
    decrypted_sequences = []
    for ciphertext in sequences:
        decrypted_sequence = decrypt_message(ciphertext, private_key, w, p)
        decrypted_sequences.append(decrypted_sequence)
    
    # Convert all decrypted sequences to text
    bytes_data = bytearray()
    for sequence in decrypted_sequences:
        for val in sequence:
            if val == 0:
                continue  # Skip zeros as they might be padding
            bytes_data.append(val)
    
    # Decode bytes to text
    try:
        return bytes_data.decode('utf-8')
    except UnicodeDecodeError:
        # Handle cases where decoding fails
        return ''.join(chr(b) if b < 128 else '?' for b in bytes_data)

def encrypt_text(text, public_key, w, p, n):
    """
    Encrypt text of any length using block-mode encryption.
    
    Args:
        text (str): Text to encrypt
        public_key (tuple): Public key (G, A)
        w (int): Primitive n-th root of unity
        p (int): Prime modulus
        n (int): Sequence length
    
    Returns:
        list: List of ciphertext pairs (C1, C2)
    """
    # Encode text to sequences
    sequences = encode_text_to_sequences(text, n, p)
    
    # Encrypt each sequence
    encrypted_sequences = []
    for sequence in sequences:
        ciphertext = encrypt_message(sequence, public_key, w, p)
        encrypted_sequences.append(ciphertext)
    
    return encrypted_sequences

def decode_sequence_to_text(sequences):
    """
    Decode a list of sequences to text.
    
    Args:
        sequences (list): List of sequences
    
    Returns:
        str: Decoded text
    """
    # Convert sequences to bytes
    bytes_data = bytearray()
    for sequence in sequences:
        for val in sequence:
            if val == 0:
                continue  # Skip padding zeros
            bytes_data.append(val)
    
    # Decode bytes to text
    try:
        return bytes_data.decode('utf-8')
    except UnicodeDecodeError:
        # Handle cases where decoding fails
        return ''.join(chr(b) if b < 128 else '?' for b in bytes_data)

def main():
    print("NTT-Based Public Key Cryptography")
    print("="*50)
    
    # Set parameters
    bits = 512  # Reduced for demonstration; use 2048+ bits for real security
    n = 16      # Sequence length (must be a power of 2 for efficient NTT)
    
    print(f"\nGenerating a {bits}-bit prime where p-1 is divisible by {n}...")
    start_time = time.time()
    
    # Generate a prime p where p-1 is divisible by n
    p = find_prime_congruent(bits, n)
    print(f"Prime p = {p}")
    print(f"Time: {time.time() - start_time:.2f} seconds")
    
    print(f"\nFinding primitive {n}-th root of unity...")
    start_time = time.time()
    w = find_primitive_root(p, n)
    print(f"w = {w}")
    print(f"Time: {time.time() - start_time:.2f} seconds")
    
    # Generate a random public sequence G
    print("\nGenerating random public sequence G...")
    G = generate_random_sequence(n, p)
    print(f"G = {G}")
    
    # Key generation
    print("\nGenerating key pair...")
    private_key = secrets.randbelow(p - 1) + 1  # Private key (a)
    print(f"Private key a = {private_key}")
    
    start_time = time.time()
    private_key, public_key = generate_keys(G, private_key, w, p)
    print(f"Time to generate keys: {time.time() - start_time:.2f} seconds")
    G, A = public_key
    print(f"Public key component A = {A}")
    
    # Message encryption and decryption
    print("\nEncryption and Decryption Test:")
    
    # Test with a simple numeric message
    original_message = generate_random_sequence(n, p)
    print(f"Original message: {original_message}")
    
    # Encrypt the message
    start_time = time.time()
    ciphertext = encrypt_message(original_message, public_key, w, p)
    print(f"Encryption time: {time.time() - start_time:.2f} seconds")
    C1, C2 = ciphertext
    print(f"Ciphertext C1: {C1}")
    print(f"Ciphertext C2: {C2}")
    
    # Decrypt the message
    start_time = time.time()
    decrypted_message = decrypt_message(ciphertext, private_key, w, p)
    print(f"Decryption time: {time.time() - start_time:.2f} seconds")
    print(f"Decrypted message: {decrypted_message}")
    
    # Verify
    if original_message == decrypted_message:
        print("\nSuccess: The decrypted message matches the original!")
    else:
        print("\nError: The decrypted message does not match the original!")
    
    # Test with text
    print("\nText Encryption Test:")
    text = "Hello, NTT cryptography!"
    print(f"Original text: {text}")
    
    # Encrypt using block mode
    print("\nEncrypting with block mode...")
    start_time = time.time()
    encrypted_blocks = encrypt_text(text, public_key, w, p, n)
    print(f"Encryption time: {time.time() - start_time:.2f} seconds")
    print(f"Number of encrypted blocks: {len(encrypted_blocks)}")
    
    # Decrypt blocks
    start_time = time.time()
    decrypted_text = decrypt_and_decode_sequences(encrypted_blocks, private_key, w, p)
    print(f"Decryption time: {time.time() - start_time:.2f} seconds")
    print(f"Decrypted text: {decrypted_text}")
    
    if text == decrypted_text:
        print("\nSuccess: Text successfully encrypted and decrypted!")
    else:
        print("\nError: Text encryption/decryption failed.")
        print(f"Original: '{text}'")
        print(f"Decrypted: '{decrypted_text}'")

if __name__ == "__main__":
    main() 