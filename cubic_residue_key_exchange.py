import random
import secrets
import sympy
import hashlib
from typing import Tuple, Dict

class CubicResidueKeyExchange:
    """
    A key exchange protocol based on the hardness of the cubic residuosity problem.
    """
    
    def __init__(self, bits: int = 1024):
        """
        Initialize the protocol with parameters of the specified bit length.
        
        Args:
            bits: The bit length for each prime factor (p and q). Default is 1024 bits,
                  which results in an n of approximately 2048 bits.
        """
        self.bits = bits
        self.p, self.q, self.n, self.g = self._generate_parameters()
        
    def _generate_parameters(self) -> Tuple[int, int, int, int]:
        """
        Generate the protocol parameters:
        - p, q: large primes congruent to 2 modulo 3
        - n: product of p and q
        - g: a cubic non-residue modulo n
        
        Returns:
            Tuple containing (p, q, n, g)
        """
        # Generate p and q, ensuring they are congruent to 2 modulo 3
        p = self._generate_prime_congruent_to_2_mod_3(self.bits)
        q = self._generate_prime_congruent_to_2_mod_3(self.bits)
        
        # Compute n = p * q
        n = p * q
        
        # Find a suitable generator g (cubic non-residue modulo n)
        g = self._find_cubic_non_residue(n, p, q)
        
        return p, q, n, g
    
    def _generate_prime_congruent_to_2_mod_3(self, bits: int) -> int:
        """
        Generate a prime number of given bit length that is congruent to 2 modulo 3.
        
        Args:
            bits: The desired bit length of the prime
            
        Returns:
            A prime number p where p ≡ 2 (mod 3)
        """
        while True:
            # Generate a random odd number of specified bit length
            candidate = secrets.randbits(bits) | (1 << (bits - 1)) | 1
            
            # Ensure it's congruent to 2 modulo 3
            if candidate % 3 == 2:
                # Check if it's prime
                if sympy.isprime(candidate):
                    return candidate
            else:
                # Adjust to make it congruent to 2 modulo 3
                candidate += (2 - candidate % 3) % 3
                if sympy.isprime(candidate):
                    return candidate
    
    def _find_cubic_non_residue(self, n: int, p: int, q: int) -> int:
        """
        Find a cubic non-residue modulo n.
        
        Args:
            n: The modulus (product of p and q)
            p, q: The prime factors of n
            
        Returns:
            A number g that is a cubic non-residue modulo n
        """
        # For primes p ≡ 2 (mod 3), a number is a cubic residue if and only if
        # it's a cubic residue modulo both p and q.
        
        # Since p ≡ q ≡ 2 (mod 3), we know that for any x coprime to p,
        # exactly one of x, x^((p-2)/3+1), and x^(2*(p-2)/3+2) is a cubic residue modulo p.
        
        while True:
            g = secrets.randbelow(n - 3) + 2  # Random number between 2 and n-1
            
            if pow(g, (p-1)//3, p) != 1 or pow(g, (q-1)//3, q) != 1:
                # g is a cubic non-residue modulo at least one of p or q,
                # which means it's a cubic non-residue modulo n
                return g
    
    def get_public_params(self) -> Dict[str, int]:
        """
        Return the public parameters of the protocol.
        
        Returns:
            Dictionary containing the public parameters n and g
        """
        return {"n": self.n, "g": self.g}
    
    def generate_keypair(self, n: int, g: int) -> Tuple[int, int]:
        """
        Generate a private-public key pair for the protocol.
        
        Args:
            n: The modulus
            g: The generator
            
        Returns:
            Tuple containing (private_key, public_key)
        """
        # Choose private key a
        private_key = secrets.randbelow(n - 3) + 2  # Random number between 2 and n-1
        
        # Compute public key A = g^a mod n
        public_key = pow(g, private_key, n)
        
        return private_key, public_key
    
    def compute_shared_secret(self, private_key: int, public_key: int, n: int) -> int:
        """
        Compute the shared secret using own private key and the other party's public key.
        
        Args:
            private_key: Own private key
            public_key: Other party's public key
            n: The modulus
            
        Returns:
            The computed shared secret
        """
        # Compute K = public_key^private_key mod n
        shared_secret = pow(public_key, private_key, n)
        return shared_secret
    
    def derive_encryption_key(self, shared_secret: int, key_length: int = 32) -> bytes:
        """
        Derive an encryption key from the shared secret.
        
        Args:
            shared_secret: The computed shared secret
            key_length: Desired length of the encryption key in bytes (default: 32 bytes = 256 bits)
            
        Returns:
            A byte string containing the derived encryption key
        """
        # Convert the shared secret to bytes and hash it
        shared_secret_bytes = shared_secret.to_bytes((shared_secret.bit_length() + 7) // 8, byteorder='big')
        return hashlib.sha256(shared_secret_bytes).digest()[:key_length]


# Example usage
def demonstrate_key_exchange():
    # Initialize the protocol
    print("Initializing protocol parameters...")
    crke = CubicResidueKeyExchange(bits=1024)  # 1024-bit primes for 2048-bit modulus
    
    # Get public parameters
    params = crke.get_public_params()
    print(f"Public parameters generated:")
    print(f"  n: {params['n']} ({params['n'].bit_length()} bits)")
    print(f"  g: {params['g']}")
    
    # Alice generates her keypair
    print("\nAlice generates her keypair...")
    alice_private, alice_public = crke.generate_keypair(params['n'], params['g'])
    print(f"  Alice's private key: {alice_private}")
    print(f"  Alice's public key: {alice_public}")
    
    # Bob generates his keypair
    print("\nBob generates his keypair...")
    bob_private, bob_public = crke.generate_keypair(params['n'], params['g'])
    print(f"  Bob's private key: {bob_private}")
    print(f"  Bob's public key: {bob_public}")
    
    # Alice computes the shared secret
    print("\nAlice computes the shared secret...")
    alice_shared = crke.compute_shared_secret(alice_private, bob_public, params['n'])
    print(f"  Alice's computed shared secret: {alice_shared}")
    
    # Bob computes the shared secret
    print("\nBob computes the shared secret...")
    bob_shared = crke.compute_shared_secret(bob_private, alice_public, params['n'])
    print(f"  Bob's computed shared secret: {bob_shared}")
    
    # Verify that both computed the same secret
    print("\nVerifying shared secrets match...")
    if alice_shared == bob_shared:
        print("  SUCCESS: Shared secrets match!")
    else:
        print("  ERROR: Shared secrets do not match!")
    
    # Derive encryption keys
    alice_key = crke.derive_encryption_key(alice_shared)
    bob_key = crke.derive_encryption_key(bob_shared)
    
    print(f"\nDerived encryption keys (hex):")
    print(f"  Alice's key: {alice_key.hex()}")
    print(f"  Bob's key:   {bob_key.hex()}")
    
    if alice_key == bob_key:
        print("  SUCCESS: Encryption keys match!")
    else:
        print("  ERROR: Encryption keys do not match!")


if __name__ == "__main__":
    demonstrate_key_exchange() 