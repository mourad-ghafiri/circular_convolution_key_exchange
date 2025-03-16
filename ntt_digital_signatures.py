import hashlib
import secrets
import time
from ntt_public_key_crypto import (
    find_prime_congruent, find_primitive_root, generate_random_sequence,
    generate_keys, convolve_power, fast_pow_mod, ntt, intt
)

def hash_message_to_sequence(message, n, p):
    """
    Hash a message and convert it to a sequence of appropriate length.
    
    Args:
        message (bytes or str): Message to hash
        n (int): Length of the output sequence
        p (int): Prime modulus
    
    Returns:
        list: Sequence representation of the hash
    """
    # Ensure message is in bytes
    if isinstance(message, str):
        message = message.encode('utf-8')
    
    # Calculate SHA-256 hash
    hash_obj = hashlib.sha256(message)
    hash_bytes = hash_obj.digest()
    
    # Convert hash to a sequence of desired length
    sequence = [0] * n
    for i in range(n):
        # Use a deterministic approach to expand the hash if needed
        extended_hash = hashlib.sha256(hash_bytes + i.to_bytes(4, 'big')).digest()
        # Convert to an integer modulo p
        sequence[i] = int.from_bytes(extended_hash[:4], 'big') % p
    
    return sequence

def sign_message(message, private_key, G, w, p):
    """
    Sign a message using NTT-based digital signatures.
    
    Args:
        message (str or bytes): Message to sign
        private_key (int): Private key 'a'
        G (list): Public sequence
        w (int): Primitive n-th root of unity
        p (int): Prime modulus
    
    Returns:
        tuple: Signature as a triplet (R, S, k2)
    """
    n = len(G)
    a = private_key
    
    # Hash the message to a fixed-length sequence
    H = hash_message_to_sequence(message, n, p)
    
    # Choose random values k1 and k2
    k1 = secrets.randbelow(p - 1) + 1
    k2 = secrets.randbelow(p - 1) + 1
    
    # Compute R = G^{*k1}
    R = convolve_power(G, k1, w, p)
    
    # Compute S = H ⊕ (G^{*k2})^{*a}
    G_k2 = convolve_power(G, k2, w, p)
    G_k2_a = convolve_power(G_k2, a, w, p)
    S = [(H[i] + G_k2_a[i]) % p for i in range(n)]
    
    return (R, S, k2)

def verify_signature(message, signature, public_key, G, w, p):
    """
    Verify a message signature using the public key.
    
    Args:
        message (str or bytes): Message to verify
        signature (tuple): Signature triplet (R, S, k2)
        public_key (list): Public key component A = G^{*a}
        G (list): Public sequence
        w (int): Primitive n-th root of unity
        p (int): Prime modulus
    
    Returns:
        bool: True if the signature is valid, False otherwise
    """
    n = len(G)
    R, S, k2 = signature
    A = public_key[1]  # A = G^{*a}
    
    # Hash the message to a fixed-length sequence
    H = hash_message_to_sequence(message, n, p)
    
    # Compute verification sequence: G^{*k2} convolved a times
    G_k2 = convolve_power(G, k2, w, p)
    G_k2_a = convolve_power(G_k2, 1, w, p)  # we'll use A directly
    
    # Compute A^{*k2}
    A_k2 = convolve_power(A, k2, w, p)
    
    # Compute V = S ⊖ A^{*k2}
    V = [(S[i] - A_k2[i]) % p for i in range(n)]
    
    # Check if V equals H
    return V == H

def sign_file(filename, private_key, G, w, p):
    """
    Sign a file using NTT-based digital signatures.
    
    Args:
        filename (str): Path to the file to sign
        private_key (int): Private key 'a'
        G (list): Public sequence
        w (int): Primitive n-th root of unity
        p (int): Prime modulus
    
    Returns:
        tuple: Signature as a triplet (R, S, k2)
    """
    with open(filename, 'rb') as file:
        file_content = file.read()
    
    return sign_message(file_content, private_key, G, w, p)

def verify_file_signature(filename, signature, public_key, G, w, p):
    """
    Verify a file signature using the public key.
    
    Args:
        filename (str): Path to the file to verify
        signature (tuple): Signature triplet (R, S, k2)
        public_key (list): Public key component A = G^{*a}
        G (list): Public sequence
        w (int): Primitive n-th root of unity
        p (int): Prime modulus
    
    Returns:
        bool: True if the signature is valid, False otherwise
    """
    with open(filename, 'rb') as file:
        file_content = file.read()
    
    return verify_signature(file_content, signature, public_key, G, w, p)

def main():
    print("NTT-Based Digital Signatures")
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
    A = public_key[1]  # Public key component A = G^{*a}
    print(f"Public key component A = {A}")
    
    # Test signing and verification with a simple message
    message = "This is a secure message signed with NTT-based digital signatures."
    print(f"\nOriginal message: {message}")
    
    # Sign the message
    print("\nSigning the message...")
    start_time = time.time()
    signature = sign_message(message, private_key, G, w, p)
    print(f"Signing time: {time.time() - start_time:.2f} seconds")
    R, S, k2 = signature
    print(f"Signature R component (first few elements): {R[:3]}...")
    print(f"Signature S component (first few elements): {S[:3]}...")
    print(f"Signature k2 component: {k2}")
    
    # Verify the signature
    print("\nVerifying the signature...")
    start_time = time.time()
    is_valid = verify_signature(message, signature, public_key, G, w, p)
    print(f"Verification time: {time.time() - start_time:.2f} seconds")
    
    if is_valid:
        print("✓ Signature is valid! The message is authentic.")
    else:
        print("✗ Signature is invalid! The message may have been tampered with.")
    
    # Test with modified message
    tampered_message = message + " This text was added after signing."
    print(f"\nTampered message: {tampered_message}")
    
    # Verify the signature with tampered message
    print("Verifying the signature with tampered message...")
    is_valid = verify_signature(tampered_message, signature, public_key, G, w, p)
    
    if is_valid:
        print("✓ Signature is valid! (This is a security concern - signatures should not validate tampered messages)")
    else:
        print("✗ Signature is invalid! As expected, the tampered message was detected.")

if __name__ == "__main__":
    main() 