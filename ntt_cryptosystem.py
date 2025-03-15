import random
import secrets
import hashlib
from typing import List, Tuple

class CryptoSystem:
    """
    Number Theoretic Transform (NTT) based cryptosystem implementing key exchange,
    encryption/decryption, and digital signatures.
    
    Mathematical foundation:
    - Works in a finite field GF(p) where p is a large prime
    - Uses circular convolution operations via NTT
    - Security based on the discrete logarithm problem in the NTT domain
    
    Security relies on the hardness of computing:
    - Given G and H = G^{*a}, find 'a' (the discrete logarithm problem)
    - Given G, G^{*a}, and G^{*b}, compute G^{*(a*b)} without knowing 'a' or 'b'
      (the computational Diffie-Hellman problem)
    """

    def __init__(self, bits: int = 2048, seq_length: int = 16):
        """
        Initialize the NTT-based cryptosystem.
        
        Args:
            bits (int): Bit length for the prime modulus p
            seq_length (int): Length of sequences (must be a power of 2 for efficient NTT)
            
        Mathematical setup:
        - Generates a prime p where p ≡ 1 (mod n) to ensure existence of nth roots of unity
        - Finds a primitive nth root of unity w where:
          * w^n ≡ 1 (mod p)
          * w^k ≢ 1 (mod p) for all 1 ≤ k < n
        - Creates generator sequence G of length n with elements in GF(p)
        """
        self.n = seq_length
        
        # Verify n is a power of 2 (required for efficient NTT implementation)
        if self.n & (self.n - 1) != 0:
            raise ValueError("Sequence length must be a power of 2")
            
        # Generate prime p where p-1 is divisible by n
        # This ensures the existence of nth roots of unity in GF(p)
        self.p = self._find_prime_congruent(bits, self.n)
        
        # Find primitive nth root of unity w
        # w^n ≡ 1 (mod p) and w^k ≢ 1 (mod p) for all 1 ≤ k < n
        self.w = self._find_primitive_root(self.p, self.n)
        
        # Generate public generator sequence G
        # This is analogous to the generator g in traditional Diffie-Hellman
        self.G = self._generate_random_sequence(self.n, self.p)
        
    def generate_keypair(self) -> Tuple[int, List[int]]:
        """
        Generate a keypair (private_key, public_key) for the cryptosystem.
        
        Mathematical basis:
        - Private key: a random integer a
        - Public key: P = G^{*a} = G convolved with itself 'a' times
        
        In NTT domain this becomes:
        - NTT(P) = [NTT(G)[0]^a, NTT(G)[1]^a, ..., NTT(G)[n-1]^a]
        
        Returns:
            Tuple[int, List[int]]: (private_key, public_key)
        """
        # Generate private key (random integer in range [1, p-1])
        private_key = secrets.randbelow(self.p - 1) + 1
        
        # Generate public key P = G^{*a}
        # This is a sequence of length n computed using NTT
        public_key = self.convolve_power(self.G, private_key, self.w, self.p)
        
        return private_key, public_key
    
    def share_key(self, private_key: int, other_public_key: List[int]) -> List[int]:
        """
        Compute shared key from private key and other party's public key.
        
        Mathematical process:
        - Alice has private key a and public key P_A = G^{*a}
        - Bob has private key b and public key P_B = G^{*b}
        - Alice computes shared key: K_A = P_B^{*a} = (G^{*b})^{*a} = G^{*(a*b)}
        - Bob computes shared key: K_B = P_A^{*b} = (G^{*a})^{*b} = G^{*(a*b)}
        - K_A = K_B = shared secret
        
        Args:
            private_key (int): Own private key (a)
            other_public_key (List[int]): Other party's public key (P_B = G^{*b})
            
        Returns:
            List[int]: Shared secret key (K = G^{*(a*b)})
        """
        # Compute other_public_key^{*private_key} = (G^{*b})^{*a} = G^{*(a*b)}
        return self.convolve_power(other_public_key, private_key, self.w, self.p)
    
    def encrypt(self, message: List[int], shared_key: List[int]) -> List[int]:
        """
        Encrypt a message using the shared key.
        
        Mathematical operation:
        - Compute C = M ⊗ K where:
          * M is the message sequence
          * K is the shared key sequence
          * ⊗ represents circular convolution
        
        In NTT domain:
        - NTT(C) = NTT(M) · NTT(K)  (point-wise multiplication)
        
        Args:
            message (List[int]): Message to encrypt (as sequence in GF(p))
            shared_key (List[int]): Shared secret key
            
        Returns:
            List[int]]: Encrypted message
        """
        # Ensure message is of correct length
        if len(message) != self.n:
            raise ValueError(f"Message must be of length {self.n}")
            
        # Convert message to NTT domain: NTT(M)
        message_ntt = self.ntt(message, self.w, self.p)
        
        # Convert key to NTT domain: NTT(K)
        key_ntt = self.ntt(shared_key, self.w, self.p)
        
        # Multiply elementwise in NTT domain: NTT(C) = NTT(M) · NTT(K)
        encrypted_ntt = [(m * k) % self.p for m, k in zip(message_ntt, key_ntt)]
        
        # Convert back to time domain: C = INTT(NTT(C))
        encrypted = self.intt(encrypted_ntt, self.w, self.p)
        
        return encrypted
    
    def decrypt(self, ciphertext: List[int], shared_key: List[int]) -> List[int]:
        """
        Decrypt a message using the shared key.
        
        Mathematical operation:
        - Compute M = C ⊘ K where:
          * C is the ciphertext sequence
          * K is the shared key sequence
          * ⊘ represents deconvolution (convolution with the inverse)
        
        In NTT domain:
        - NTT(M) = NTT(C) / NTT(K)  (point-wise division)
        
        Args:
            ciphertext (List[int]): Encrypted message
            shared_key (List[int]): Shared secret key
            
        Returns:
            List[int]: Decrypted message
        """
        # For decryption, we need the multiplicative inverse of the key in NTT domain
        # NTT(K)^(-1) = [1/NTT(K)[0], 1/NTT(K)[1], ..., 1/NTT(K)[n-1]]
        key_ntt = self.ntt(shared_key, self.w, self.p)
        key_inv_ntt = [self._mod_inverse(k, self.p) for k in key_ntt]
        
        # Convert ciphertext to NTT domain: NTT(C)
        ciphertext_ntt = self.ntt(ciphertext, self.w, self.p)
        
        # Multiply by inverse key: NTT(M) = NTT(C) · NTT(K)^(-1)
        decrypted_ntt = [(c * k_inv) % self.p for c, k_inv in zip(ciphertext_ntt, key_inv_ntt)]
        
        # Convert back to time domain: M = INTT(NTT(M))
        decrypted = self.intt(decrypted_ntt, self.w, self.p)
        
        return decrypted
    
    def sign(self, message: List[int], private_key: int) -> Tuple[List[int], int]:
        """
        Sign a message using a robust Schnorr-like NTT-based signature scheme.
        
        Mathematical basis (Schnorr signature adapted to NTT domain):
        1. Choose random ephemeral key k
        2. Compute commitment r = G^{*k}
        3. Compute challenge e = H(digest || r) where H is a hash function
        4. Compute response s = (k + e·a) mod (p-1) where a is private key
        
        Security relies on the hardness of:
        - The discrete logarithm problem in the NTT domain
        - The binding property of the hash function
        
        Args:
            message (List[int]): Message to sign
            private_key (int): Private key
            
        Returns:
            Tuple[List[int], int]: Signature (r, s)
        """
        # Hash the message to create a fixed-length digest
        # This ensures the signature works for messages of any length
        digest = self._hash_to_sequence(message)
        
        # Generate a random ephemeral key (nonce) that's relatively prime to (p-1)
        # This ensures the nonce is invertible modulo (p-1)
        ephemeral_key = secrets.randbelow(self.p - 2) + 1
        while self._gcd(ephemeral_key, self.p - 1) != 1:
            ephemeral_key = secrets.randbelow(self.p - 2) + 1
        
        # Compute commitment r = G^{*ephemeral_key}
        # This is analogous to r = g^k mod p in standard Schnorr signatures
        r = self.convolve_power(self.G, ephemeral_key, self.w, self.p)
        
        # Compute challenge e = H(digest || r)
        # This binds both the message and the commitment to the signature
        combined = digest.copy()
        combined.extend(r)
        e = self._hash_to_int(combined)
        
        # Compute response s = (k + e·a) mod (p-1)
        # This proves knowledge of the private key without revealing it
        s = (ephemeral_key + (e * private_key) % (self.p - 1)) % (self.p - 1)
        
        # Return (r, s) as the signature
        # r is a commitment sequence, s is a scalar response
        return (r, s)
    
    def verify(self, message: List[int], signature: Tuple[List[int], int], 
               public_key: List[int]) -> bool:
        """
        Verify a signature using public key.
        
        Mathematical verification:
        1. Compute challenge e = H(digest || r)
        2. Check if G^s = r ⊗ (P^e)
        
        This works because:
        - G^s = G^(k + e·a) = G^k ⊗ G^(e·a) = r ⊗ (P^e)
        
        Where:
        - s = k + e·a mod (p-1)
        - r = G^k
        - P = G^a (public key)
        
        Args:
            message (List[int]): Original message
            signature (Tuple[List[int], int]): Signature components (r, s)
            public_key (List[int]): Signer's public key
            
        Returns:
            bool: True if signature is valid, False otherwise
        """
        # Unpack signature components
        r, s = signature
        
        # Basic validation of signature format
        if not isinstance(r, list) or len(r) != self.n:
            return False
        
        # Hash the message to create a fixed-length digest
        # Must use the same hashing method as in sign()
        digest = self._hash_to_sequence(message)
        
        # Compute challenge e = H(digest || r)
        # This recreates the challenge from the signature process
        combined = digest.copy()
        combined.extend(r)
        e = self._hash_to_int(combined)
        
        # Compute left side of verification equation: G^s
        g_s = self.convolve_power(self.G, s, self.w, self.p)
        
        # Compute right side, part 1: public_key^e = (G^a)^e = G^(a·e)
        pub_e = self.convolve_power(public_key, e, self.w, self.p)
        
        # Compute right side, part 2: r ⊗ public_key^e = G^k ⊗ G^(a·e) = G^(k + a·e)
        r_pub_e = self._convolve(r, pub_e, self.w, self.p)
        
        # Verify: G^s = r ⊗ public_key^e
        # This confirms that s = k + a·e mod (p-1) without knowing k or a
        return self._sequences_equal(g_s, r_pub_e)
    
    def _hash_to_int(self, data: List[int]) -> int:
        """
        Hash a sequence to a single integer modulo (p-1).
        
        Mathematical property:
        - Maps an arbitrary sequence to a "random oracle" output in Z_{p-1}
        - Needed for the Schnorr signature challenge value
        
        Args:
            data (List[int]): Input data
            
        Returns:
            int: Integer derived from hash, in range [0, p-2]
        """
        # Convert data to string for consistent hashing
        data_str = ','.join(str(val) for val in data)
        hash_bytes = hashlib.sha256(data_str.encode('utf-8')).digest()
        
        # Convert to integer and reduce modulo (p-1)
        # This ensures the result is in the correct range for exponents
        hash_int = int.from_bytes(hash_bytes, byteorder='big')
        return hash_int % (self.p - 1)
    
    def _sequences_equal(self, seq1: List[int], seq2: List[int]) -> bool:
        """
        Compare two sequences for equality with tolerance for numerical precision.
        
        Args:
            seq1 (List[int]): First sequence
            seq2 (List[int]): Second sequence
            
        Returns:
            bool: True if sequences are element-wise equal
        """
        if len(seq1) != len(seq2):
            return False
        
        for i in range(len(seq1)):
            if seq1[i] != seq2[i]:
                return False
        
        return True
    
    def _convolve(self, a: List[int], b: List[int], w: int, p: int) -> List[int]:
        """
        Compute circular convolution of two sequences using NTT.
        
        Mathematical operation:
        - c = a ⊗ b (circular convolution)
        
        In NTT domain:
        - NTT(c) = NTT(a) · NTT(b) (point-wise multiplication)
        - c = INTT(NTT(c))
        
        Args:
            a (List[int]): First sequence
            b (List[int]): Second sequence
            w (int): Primitive n-th root of unity
            p (int): Prime modulus
            
        Returns:
            List[int]: Convolution result c = a ⊗ b
        """
        # Transform both sequences to NTT domain
        a_ntt = self.ntt(a, w, p)
        b_ntt = self.ntt(b, w, p)
        
        # Multiply point-wise in NTT domain
        # This is equivalent to circular convolution in time domain
        c_ntt = [(a_val * b_val) % p for a_val, b_val in zip(a_ntt, b_ntt)]
        
        # Transform back to time domain
        c = self.intt(c_ntt, w, p)
        return c
    
    def _hash_to_sequence(self, data: List[int]) -> List[int]:
        """
        Hash arbitrary data to a sequence of length n.
        
        Mathematical purpose:
        - Creates a "random oracle" mapping from input data to a sequence in GF(p)^n
        - Used for message digests in signatures
        
        Args:
            data (List[int]): Input data
            
        Returns:
            List[int]: Sequence of length n derived from the hash, with elements in GF(p)
        """
        # Create a SHA-256 hash object
        hash_obj = hashlib.sha256()
        
        # Convert data to string (reliable way to handle large integers)
        data_str = ','.join(str(val) for val in data)
        hash_obj.update(data_str.encode('utf-8'))
        
        # Get the digest as a seed for further hashing
        hash_digest = hash_obj.digest()
        
        # Expand the hash to the required length using multiple hashes
        # This is similar to a key derivation function
        result = []
        for i in range(self.n):
            # Create a unique hash for each position
            # This ensures the output sequence has high entropy in each position
            position_hash = hashlib.sha256()
            position_hash.update(hash_digest + str(i).encode('utf-8'))
            position_digest = position_hash.digest()
            
            # Convert to a large integer and reduce modulo p
            # This ensures the result is in the correct range for GF(p)
            val = int.from_bytes(position_digest, byteorder='big') % self.p
            result.append(val)
        
        return result

    def _mod_inverse(self, a: int, m: int) -> int:
        """
        Compute the multiplicative inverse of a modulo m.
        
        Mathematical operation:
        - Find x such that a·x ≡ 1 (mod m)
        - Uses the extended Euclidean algorithm
        
        Args:
            a (int): Number to invert
            m (int): Modulus
            
        Returns:
            int: Multiplicative inverse of a modulo m, a^(-1) such that a·a^(-1) ≡ 1 (mod m)
        """
        g, x, y = self._extended_gcd(a, m)
        if g != 1:
            raise ValueError(f"Modular inverse does not exist for {a} mod {m}")
        else:
            return x % m
    
    def _extended_gcd(self, a: int, b: int) -> Tuple[int, int, int]:
        """
        Extended Euclidean algorithm to find gcd and coefficients.
        
        Mathematical result:
        - Computes integers x, y such that ax + by = gcd(a, b)
        
        Args:
            a (int): First number
            b (int): Second number
            
        Returns:
            Tuple[int, int, int]: (gcd, x, y) where ax + by = gcd
        """
        if a == 0:
            return b, 0, 1
        else:
            gcd, x1, y1 = self._extended_gcd(b % a, a)
            x = y1 - (b // a) * x1
            y = x1
            return gcd, x, y

    def ntt(self, A: List[int], w: int, p: int) -> List[int]:
        """
        Iterative implementation of Number Theoretic Transform.
        
        Mathematical definition:
        - For a sequence A of length n, its NTT is:
          NTT(A)[k] = ∑_{j=0}^{n-1} A[j] * w^(j*k) mod p, for k = 0,1,...,n-1
        
        Implemented using Cooley-Tukey FFT algorithm adapted for NTT.
        
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
        # Rearranges the elements to optimize the butterfly operations
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
        # Performs in-place computation of the NTT
        for s in range(1, n.bit_length()):
            m = 1 << s  # 2^s
            w_m = self._fast_pow_mod(w, (p - 1) // m, p)
            
            for k in range(0, n, m):
                omega = 1
                for j in range(m // 2):
                    t = (omega * A_copy[k + j + m // 2]) % p
                    u = A_copy[k + j]
                    A_copy[k + j] = (u + t) % p
                    A_copy[k + j + m // 2] = (u - t) % p
                    omega = (omega * w_m) % p
        
        return A_copy
    
    def intt(self, B: List[int], w: int, p: int) -> List[int]:
        """
        Inverse Number Theoretic Transform.
        
        Mathematical definition:
        - For a sequence B in the NTT domain, its INTT is:
          INTT(B)[j] = (1/n) * ∑_{k=0}^{n-1} B[k] * w^(-j*k) mod p, for j = 0,1,...,n-1
        
        Args:
            B (list): Input sequence in frequency domain
            w (int): Primitive n-th root of unity
            p (int): Prime modulus
            
        Returns:
            list: Inverse NTT of B
        """
        n = len(B)
        
        # Compute the inverse of w: w^(-1) mod p
        w_inv = self._mod_inverse(w, p)
        
        # Compute the inverse of n: n^(-1) mod p
        n_inv = self._mod_inverse(n, p)
        
        # Compute INTT using NTT with inverse root
        # INTT(B) = (1/n) * NTT(B, w^(-1))
        result = self.ntt(B, w_inv, p)
        
        # Scale by 1/n
        for i in range(n):
            result[i] = (result[i] * n_inv) % p
        
        return result
    
    def convolve_power(self, G: List[int], a: int, w: int, p: int) -> List[int]:
        """
        Compute G^{*a}, the sequence G convolved with itself a times.
        
        Mathematical operation:
        - Computes the a-th power of sequence G under circular convolution
        - In NTT domain: NTT(G^{*a})[k] = NTT(G)[k]^a for all k
        
        This is the core operation for key generation, shared key computation, and signatures.
        
        Args:
            G (list): Base sequence
            a (int): Exponent (number of convolutions)
            w (int): Primitive n-th root of unity
            p (int): Prime modulus
            
        Returns:
            list: Result of G^{*a}
        """
        # Transform G to frequency domain
        F_G = self.ntt(G, w, p)
        
        # Pointwise exponentiation in frequency domain
        # This is equivalent to repeated convolution in time domain
        F_Ga = [self._fast_pow_mod(f, a, p) for f in F_G]
        
        # Transform back to time domain
        Ga = self.intt(F_Ga, w, p)
        
        return Ga

    def _fast_pow_mod(self, base: int, exponent: int, modulus: int) -> int:
        """
        Efficiently compute (base^exponent) % modulus using square-and-multiply algorithm.
        
        Mathematical operation:
        - Computes base^exponent mod modulus in O(log(exponent)) time
        
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

    def _gcd(self, a: int, b: int) -> int:
        """
        Calculate the greatest common divisor of two numbers.
        
        Mathematical definition:
        - gcd(a,b) is the largest positive integer that divides both a and b
        
        Args:
            a (int): First number
            b (int): Second number
            
        Returns:
            int: Greatest common divisor
        """
        while b:
            a, b = b, a % b
        return a
        
    def _find_prime_congruent(self, bits: int, n: int) -> int:
        """
        Find a prime number p of specified bit length where p-1 is divisible by n.
        
        Mathematical property:
        - Ensures the existence of n-th roots of unity in GF(p)
        - Specifically, a primitive n-th root of unity w exists where:
          * w^n ≡ 1 (mod p)
          * w^k ≢ 1 (mod p) for all 1 ≤ k < n
        
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
                
            if self._is_prime(p):
                return p
    
    def _is_prime(self, n: int, k: int = 40) -> bool:
        """
        Miller-Rabin primality test.
        
        Mathematical basis:
        - Probabilistic primality test based on Fermat's little theorem
        - For prime p and any a not divisible by p: a^(p-1) ≡ 1 (mod p)
        - Extended to check stronger conditions using the decomposition p-1 = 2^r * d
        
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
            x = self._fast_pow_mod(a, d, n)
            
            if x == 1 or x == n - 1:
                continue
            
            for _ in range(r - 1):
                x = self._fast_pow_mod(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
        
        return True
    
    def _find_primitive_root(self, p: int, n: int) -> int:
        """
        Find a primitive n-th root of unity modulo p.
        
        Mathematical property:
        - A primitive n-th root of unity w satisfies:
          * w^n ≡ 1 (mod p)
          * w^k ≢ 1 (mod p) for all 1 ≤ k < n
        
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
            if self._fast_pow_mod(g, (p - 1) // 2, p) != 1:
                break
            g += 1
            attempts += 1
        
        if attempts == max_attempts:
            raise ValueError("Failed to find a generator of the multiplicative group")
        
        # Compute w = g^((p-1)/n) mod p
        # This gives a primitive n-th root of unity
        w = self._fast_pow_mod(g, (p - 1) // n, p)
        
        # Verify w is a primitive n-th root of unity
        if self._fast_pow_mod(w, n, p) != 1:
            raise ValueError("Failed to find primitive n-th root of unity")
        
        return w
    
    def _generate_random_sequence(self, length: int, prime: int) -> List[int]:
        """
        Generate a random sequence of specified length with elements in GF(p).
        
        Args:
            length (int): Length of the sequence
            prime (int): Prime modulus
            
        Returns:
            list: Random sequence with elements in range [1, prime-1]
        """
        return [random.randint(1, prime-1) for _ in range(length)] 
