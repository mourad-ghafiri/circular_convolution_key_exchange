import random
import secrets
import time
import math
from ntt_key_exchange_large import (
    fast_pow_mod, ntt, convolve_power, generate_random_sequence,
    find_primitive_root, find_prime_congruent, is_prime
)

class Eve:
    """
    Class representing Eve, the eavesdropper, who can listen to the communications
    between Alice and Bob but cannot modify them.
    """
    
    def __init__(self, p, n, w, G, Ga, Gb):
        """
        Initialize Eve with the public parameters and the values exchanged between Alice and Bob.
        
        Args:
            p (int): Prime modulus
            n (int): Sequence length
            w (int): Primitive n-th root of unity
            G (list): Public base sequence
            Ga (list): Alice's public value G^{*a}
            Gb (list): Bob's public value G^{*b}
        """
        self.p = p
        self.n = n
        self.w = w
        self.G = G
        self.Ga = Ga
        self.Gb = Gb
        
    def brute_force_attack(self, max_attempts=1000):
        """
        Method 1: Brute force attack.
        Try different values for 'a' until we find one that matches Ga.
        
        Args:
            max_attempts (int): Maximum number of attempts before giving up
        
        Returns:
            tuple: (success, secret_key, shared_key, time_taken)
        """
        print("\n=== Method 1: Brute Force Attack ===")
        print(f"Attempting to find Alice's secret key by testing up to {max_attempts} values...")
        
        start_time = time.time()
        
        # Convert Ga to frequency domain for faster comparison
        F_Ga = ntt(self.Ga, self.w, self.p)
        F_G = ntt(self.G, self.w, self.p)
        
        for a_guess in range(1, max_attempts + 1):
            if a_guess % 100 == 0:
                elapsed = time.time() - start_time
                print(f"Tried {a_guess} values in {elapsed:.2f} seconds...")
            
            # Instead of computing full convolution, just check if frequencies match
            F_Ga_guess = [fast_pow_mod(f, a_guess, self.p) for f in F_G]
            
            if F_Ga_guess == F_Ga:
                # We found Alice's key!
                secret_key = a_guess
                # Compute the shared key using Bob's public value
                shared_key = convolve_power(self.Gb, secret_key, self.w, self.p)
                time_taken = time.time() - start_time
                
                print(f"Success! Found Alice's secret key: {secret_key}")
                print(f"Time taken: {time_taken:.2f} seconds")
                return True, secret_key, shared_key, time_taken
        
        time_taken = time.time() - start_time
        print(f"Failed to find the key within {max_attempts} attempts.")
        print(f"Time taken: {time_taken:.2f} seconds")
        return False, None, None, time_taken
    
    def baby_step_giant_step(self, max_range=1000):
        """
        Method 2: Baby-step Giant-step algorithm for discrete logarithm.
        This is a time-space tradeoff compared to brute force.
        
        Args:
            max_range (int): Maximum range to search
        
        Returns:
            tuple: (success, secret_key, shared_key, time_taken)
        """
        print("\n=== Method 2: Baby-Step Giant-Step Attack ===")
        print(f"Attempting to solve the discrete logarithm problem with range {max_range}...")
        
        start_time = time.time()
        
        # We work in the frequency domain where convolution becomes multiplication
        F_G = ntt(self.G, self.w, self.p)
        F_Ga = ntt(self.Ga, self.w, self.p)
        
        # Choose the first non-zero element for simplicity
        idx = 0
        for i, (g, ga) in enumerate(zip(F_G, F_Ga)):
            if g != 0:
                idx = i
                break
        
        g = F_G[idx]
        ga = F_Ga[idx]
        
        # Baby-step Giant-step algorithm to find 'a' where g^a = ga (mod p)
        m = int(math.sqrt(max_range)) + 1
        
        # Precompute baby steps: g^j for 0 <= j < m
        baby_steps = {}
        for j in range(m):
            baby_steps[fast_pow_mod(g, j, self.p)] = j
        
        # Compute g^(-m) using Fermat's Little Theorem
        g_inv_m = fast_pow_mod(fast_pow_mod(g, self.p - 2, self.p), m, self.p)
        
        # Giant steps
        for i in range(m):
            # Compute ga * (g^(-m))^i
            value = (ga * fast_pow_mod(g_inv_m, i, self.p)) % self.p
            
            if value in baby_steps:
                # We found a solution: a = i*m + j
                a_guess = i * m + baby_steps[value]
                
                # Verify if this is actually Alice's key by checking the entire sequence
                F_Ga_guess = [fast_pow_mod(f, a_guess, self.p) for f in F_G]
                
                if F_Ga_guess == F_Ga:
                    # We found Alice's key!
                    secret_key = a_guess
                    # Compute the shared key using Bob's public value
                    shared_key = convolve_power(self.Gb, secret_key, self.w, self.p)
                    time_taken = time.time() - start_time
                    
                    print(f"Success! Found Alice's secret key: {secret_key}")
                    print(f"Time taken: {time_taken:.2f} seconds")
                    return True, secret_key, shared_key, time_taken
        
        time_taken = time.time() - start_time
        print(f"Failed to find the key within range {max_range}.")
        print(f"Time taken: {time_taken:.2f} seconds")
        return False, None, None, time_taken
    
    def meet_in_the_middle_attack(self, max_range=1000):
        """
        Method 3: Meet-in-the-Middle attack.
        This is another time-space tradeoff that can be effective for 
        solving the general DLP problem.
        
        Args:
            max_range (int): Maximum range to search
        
        Returns:
            tuple: (success, secret_key, shared_key, time_taken)
        """
        print("\n=== Method 3: Meet-in-the-Middle Attack ===")
        print(f"Attempting to perform a meet-in-the-middle attack with range {max_range}...")
        
        start_time = time.time()
        
        # Pick a more tractable subproblem: solve for a single element
        # We split the problem: find k1, k2 such that a = k1 + k2*max_bound
        # where k1 < sqrt(max_range) and k2 < sqrt(max_range)
        max_bound = int(math.sqrt(max_range)) + 1
        
        # We work in the frequency domain where convolution becomes multiplication
        F_G = ntt(self.G, self.w, self.p)
        F_Ga = ntt(self.Ga, self.w, self.p)
        
        # Choose the first non-zero element for simplicity
        idx = 0
        for i, (g, ga) in enumerate(zip(F_G, F_Ga)):
            if g != 0:
                idx = i
                break
        
        g = F_G[idx]
        ga = F_Ga[idx]
        
        # Build lookup table for g^(k1)
        lookup = {}
        for k1 in range(max_bound):
            lookup[fast_pow_mod(g, k1, self.p)] = k1
        
        # Compute g^max_bound
        g_m = fast_pow_mod(g, max_bound, self.p)
        
        # Look for matches
        for k2 in range(max_bound):
            # Calculate ga / (g^m)^k2
            right_side = (ga * fast_pow_mod(fast_pow_mod(g_m, k2, self.p), self.p - 2, self.p)) % self.p
            
            if right_side in lookup:
                k1 = lookup[right_side]
                a_guess = k1 + k2 * max_bound
                
                # Verify if this is actually Alice's key by checking the entire sequence
                F_Ga_guess = [fast_pow_mod(f, a_guess, self.p) for f in F_G]
                
                if F_Ga_guess == F_Ga:
                    # We found Alice's key!
                    secret_key = a_guess
                    # Compute the shared key using Bob's public value
                    shared_key = convolve_power(self.Gb, secret_key, self.w, self.p)
                    time_taken = time.time() - start_time
                    
                    print(f"Success! Found Alice's secret key: {secret_key}")
                    print(f"Time taken: {time_taken:.2f} seconds")
                    return True, secret_key, shared_key, time_taken
        
        time_taken = time.time() - start_time
        print(f"Failed to find the key within range {max_range}.")
        print(f"Time taken: {time_taken:.2f} seconds")
        return False, None, None, time_taken
    
    def pollards_rho_attack(self, max_iterations=1000):
        """
        Method 4: Pollard's Rho Algorithm for discrete logarithm.
        A probabilistic algorithm with O(1) space complexity.
        
        Args:
            max_iterations (int): Maximum number of iterations before giving up
        
        Returns:
            tuple: (success, secret_key, shared_key, time_taken)
        """
        print("\n=== Method 4: Pollard's Rho Attack ===")
        print(f"Attempting to solve the discrete logarithm problem with up to {max_iterations} iterations...")
        
        start_time = time.time()
        
        # We work in the frequency domain where convolution becomes multiplication
        F_G = ntt(self.G, self.w, self.p)
        F_Ga = ntt(self.Ga, self.w, self.p)
        
        # Choose the first non-zero element for simplicity
        idx = 0
        for i, (g, ga) in enumerate(zip(F_G, F_Ga)):
            if g != 0:
                idx = i
                break
        
        g = F_G[idx]
        h = F_Ga[idx]  # h = g^a, we want to find a
        
        # Define the iteration function f(x, a, b) that maps triples to triples
        # We use three sets S_1, S_2, S_3 to define the iteration function
        # The triple (x, a, b) represents x = g^a * h^b
        
        # Helper function to determine which set x belongs to
        def get_set(x):
            return x % 3
        
        # Initialize starting points
        x, a, b = 1, 0, 0
        x_tortoise, a_tortoise, b_tortoise = x, a, b
        
        # Floyd's cycle-finding algorithm (tortoise and hare)
        for i in range(1, max_iterations + 1):
            # Tortoise moves one step
            set_t = get_set(x_tortoise)
            if set_t == 0:
                x_tortoise = (x_tortoise * g) % self.p
                a_tortoise = (a_tortoise + 1) % (self.p - 1)
            elif set_t == 1:
                x_tortoise = (x_tortoise * x_tortoise) % self.p
                a_tortoise = (a_tortoise * 2) % (self.p - 1)
                b_tortoise = (b_tortoise * 2) % (self.p - 1)
            else:  # set_t == 2
                x_tortoise = (x_tortoise * h) % self.p
                b_tortoise = (b_tortoise + 1) % (self.p - 1)
            
            # Hare moves two steps
            for _ in range(2):
                set_h = get_set(x)
                if set_h == 0:
                    x = (x * g) % self.p
                    a = (a + 1) % (self.p - 1)
                elif set_h == 1:
                    x = (x * x) % self.p
                    a = (a * 2) % (self.p - 1)
                    b = (b * 2) % (self.p - 1)
                else:  # set_h == 2
                    x = (x * h) % self.p
                    b = (b + 1) % (self.p - 1)
            
            # Check if we've found a cycle
            if x_tortoise == x:
                # We have a cycle, now solve for the discrete logarithm
                if b_tortoise == b:
                    # If b_tortoise == b, we can't solve for a
                    continue
                
                # Solve for a: g^a_tortoise * h^b_tortoise = g^a * h^b
                # This gives: a_tortoise + a*b_tortoise = a + b*a (mod p-1)
                # Rearranging: a(b_tortoise - b) = a_tortoise - a (mod p-1)
                # So: a = (a_tortoise - a) * inverse(b - b_tortoise) (mod p-1)
                
                b_diff = (b - b_tortoise) % (self.p - 1)
                a_diff = (a_tortoise - a) % (self.p - 1)
                
                # Calculate the modular inverse of b_diff
                try:
                    b_diff_inv = fast_pow_mod(b_diff, self.p - 3, self.p - 1)  # Using Fermat's Little Theorem for p-1
                    a_guess = (a_diff * b_diff_inv) % (self.p - 1)
                    
                    # Verify if this is actually Alice's key by checking the entire sequence
                    F_Ga_guess = [fast_pow_mod(f, a_guess, self.p) for f in F_G]
                    
                    if F_Ga_guess == F_Ga:
                        # We found Alice's key!
                        secret_key = a_guess
                        # Compute the shared key using Bob's public value
                        shared_key = convolve_power(self.Gb, secret_key, self.w, self.p)
                        time_taken = time.time() - start_time
                        
                        print(f"Success! Found Alice's secret key: {secret_key}")
                        print(f"Time taken: {time_taken:.2f} seconds")
                        return True, secret_key, shared_key, time_taken
                except:
                    # If b_diff has no inverse, we can't solve for a
                    continue
            
            if i % 100 == 0:
                elapsed = time.time() - start_time
                print(f"Completed {i} iterations in {elapsed:.2f} seconds...")
        
        time_taken = time.time() - start_time
        print(f"Failed to find the key within {max_iterations} iterations.")
        print(f"Time taken: {time_taken:.2f} seconds")
        return False, None, None, time_taken
    
    def index_calculus_attack(self, max_relations=50, factor_base_size=10):
        """
        Method 5: Index Calculus Attack.
        A sophisticated algorithm for solving discrete logarithm problems in finite fields.
        
        Args:
            max_relations (int): Maximum number of relations to collect
            factor_base_size (int): Size of the factor base of small primes
        
        Returns:
            tuple: (success, secret_key, shared_key, time_taken)
        """
        print("\n=== Method 5: Index Calculus Attack ===")
        print(f"Attempting to solve the discrete logarithm problem using index calculus...")
        print(f"Factor base size: {factor_base_size}, Max relations: {max_relations}")
        
        start_time = time.time()
        
        # We work in the frequency domain where convolution becomes multiplication
        F_G = ntt(self.G, self.w, self.p)
        F_Ga = ntt(self.Ga, self.w, self.p)
        
        # Choose the first non-zero element for simplicity
        idx = 0
        for i, (g, ga) in enumerate(zip(F_G, F_Ga)):
            if g != 0:
                idx = i
                break
        
        g = F_G[idx]
        h = F_Ga[idx]  # h = g^a, we want to find a
        
        # Step 1: Generate a factor base of small primes
        print("Generating factor base of small primes...")
        factor_base = []
        prime = 2
        while len(factor_base) < factor_base_size:
            # Check if prime is in the field and is a quadratic residue
            if prime < self.p and is_quadratic_residue(prime, self.p):
                factor_base.append(prime)
            prime = next_prime(prime)
        
        print(f"Factor base: {factor_base}")
        
        # Step 2: Collect relations
        print("Collecting relations...")
        relations = []
        exponents = []
        
        for _ in range(max_relations):
            # Generate a random exponent k
            k = random.randint(2, self.p - 2)
            
            # Compute g^k mod p
            gk = fast_pow_mod(g, k, self.p)
            
            # Try to factor gk over the factor base
            factors, success = factor_over_base(gk, factor_base, self.p)
            
            if success:
                relations.append(factors)
                exponents.append(k)
                if len(relations) % 10 == 0:
                    print(f"Found {len(relations)} relations so far...")
            
            if len(relations) >= factor_base_size:
                break
        
        if len(relations) < factor_base_size:
            print(f"Failed to find enough relations. Found only {len(relations)}.")
            time_taken = time.time() - start_time
            print(f"Time taken: {time_taken:.2f} seconds")
            return False, None, None, time_taken
        
        # Step 3: Solve the linear system to find discrete logs of factor base elements
        print("Solving linear system for discrete logarithms of factor base elements...")
        try:
            # Convert relations to a system of linear equations mod (p-1)
            # This is a simplified version - a real implementation would use a proper
            # linear algebra library for modular arithmetic
            logs = solve_linear_system(relations, exponents, self.p - 1)
            
            # Step 4: Compute the discrete logarithm of h
            print("Computing the discrete logarithm of the target...")
            
            # Find an auxiliary value y such that h*g^y is smooth over the factor base
            for y in range(1, 1000):  # Limit the search for demonstration
                hy = (h * fast_pow_mod(g, y, self.p)) % self.p
                factors, success = factor_over_base(hy, factor_base, self.p)
                
                if success:
                    # Compute log_g(h) = (sum(e_i * log_g(p_i)) - y) mod (p-1)
                    log_h = 0
                    for prime, exponent in zip(factor_base, factors):
                        idx = factor_base.index(prime)
                        log_h = (log_h + exponent * logs[idx]) % (self.p - 1)
                    
                    a_guess = (log_h - y) % (self.p - 1)
                    
                    # Verify if this is actually Alice's key
                    if fast_pow_mod(g, a_guess, self.p) == h:
                        # Verify with the entire sequence
                        F_Ga_guess = [fast_pow_mod(f, a_guess, self.p) for f in F_G]
                        
                        if F_Ga_guess == F_Ga:
                            # We found Alice's key!
                            secret_key = a_guess
                            # Compute the shared key using Bob's public value
                            shared_key = convolve_power(self.Gb, secret_key, self.w, self.p)
                            time_taken = time.time() - start_time
                            
                            print(f"Success! Found Alice's secret key: {secret_key}")
                            print(f"Time taken: {time_taken:.2f} seconds")
                            return True, secret_key, shared_key, time_taken
            
            print("Failed to find a smooth representation of the target.")
        except Exception as e:
            print(f"Error solving the linear system: {e}")
        
        time_taken = time.time() - start_time
        print(f"Failed to find the key using index calculus.")
        print(f"Time taken: {time_taken:.2f} seconds")
        return False, None, None, time_taken

# Helper functions for the Index Calculus Attack

def is_quadratic_residue(a, p):
    """Check if a is a quadratic residue modulo p."""
    return fast_pow_mod(a, (p - 1) // 2, p) == 1

def next_prime(n):
    """Find the next prime number after n."""
    if n < 2:
        return 2
    n += 1 + (n % 2)  # Make sure n is odd
    while not is_prime(n):
        n += 2
    return n

def factor_over_base(n, factor_base, p):
    """
    Try to factor n over the factor base.
    
    Args:
        n (int): Number to factor
        factor_base (list): List of primes to use as factors
        p (int): Modulus
    
    Returns:
        tuple: (exponents, success) where exponents is a list of exponents for each prime
               in the factor base, and success is a boolean indicating if factorization succeeded
    """
    # Work with n mod p
    n = n % p
    
    # Initialize exponents
    exponents = [0] * len(factor_base)
    
    # Try to factor n
    for i, prime in enumerate(factor_base):
        while n % prime == 0:
            exponents[i] += 1
            n //= prime
    
    # Check if factorization is complete
    return exponents, n == 1

def solve_linear_system(relations, exponents, modulus):
    """
    Solve a system of linear equations modulo 'modulus'.
    This is a simplified version for demonstration purposes.
    
    Args:
        relations (list): List of relations (exponent vectors)
        exponents (list): List of exponents (right-hand side values)
        modulus (int): Modulus for calculations
    
    Returns:
        list: Solution vector (discrete logs of factor base elements)
    """
    # This is a placeholder for a real implementation
    # In practice, you would use a proper linear algebra library
    # that can handle modular arithmetic
    
    # For demonstration, we'll just return some dummy values
    # that will almost certainly fail in practice
    return [random.randint(1, modulus - 1) for _ in range(len(relations[0]))]


def simulate_key_exchange(bits=2048, n=64):
    """
    Simulate a key exchange between Alice and Bob to provide Eve with the necessary information.
    Uses real-world cryptographic parameters.
    
    Returns:
        tuple: (p, n, w, G, Ga, Gb, K_shared)
    """
    print("Simulating Key Exchange with Real-World Cryptographic Parameters")
    print("="*70)
    
    print(f"\nGenerating a {bits}-bit prime where p-1 is divisible by {n}...")
    start_time = time.time()
    p = find_prime_congruent(bits, n)
    print(f"Prime p = {p}")
    print(f"Prime generation time: {time.time() - start_time:.2f} seconds")
    
    print(f"\nFinding primitive {n}-th root of unity...")
    start_time = time.time()
    w = find_primitive_root(p, n)
    print(f"Primitive {n}-th root of unity w = {w}")
    print(f"Root finding time: {time.time() - start_time:.2f} seconds")
    
    # Generate a random public sequence G
    print("\nGenerating random public sequence G...")
    start_time = time.time()
    G = generate_random_sequence(n, p)
    print(f"Sequence generation time: {time.time() - start_time:.2f} seconds")
    
    # Alice's part - using cryptographically secure random key
    print("\nAlice generating secret key and computing G^{*a}...")
    start_time = time.time()
    a = secrets.randbelow(p - 1) + 1  # Cryptographically secure random key
    print(f"Alice's secret key bit length: {a.bit_length()} bits")
    Ga = convolve_power(G, a, w, p)
    print(f"Alice's computation time: {time.time() - start_time:.2f} seconds")
    
    # Bob's part - using cryptographically secure random key
    print("\nBob generating secret key and computing G^{*b}...")
    start_time = time.time()
    b = secrets.randbelow(p - 1) + 1  # Cryptographically secure random key
    print(f"Bob's secret key bit length: {b.bit_length()} bits")
    Gb = convolve_power(G, b, w, p)
    print(f"Bob's computation time: {time.time() - start_time:.2f} seconds")
    
    # Shared key computation
    print("\nComputing shared keys...")
    start_time = time.time()
    K_alice = convolve_power(Gb, a, w, p)
    alice_time = time.time() - start_time
    
    start_time = time.time()
    K_bob = convolve_power(Ga, b, w, p)
    bob_time = time.time() - start_time
    
    print(f"Alice's shared key computation time: {alice_time:.2f} seconds")
    print(f"Bob's shared key computation time: {bob_time:.2f} seconds")
    
    if K_alice == K_bob:
        print("Shared key successfully established!")
    else:
        print("ERROR: Shared keys do not match!")
        return None
    
    return p, n, w, G, Ga, Gb, K_alice

def main():
    # Use real-world cryptographic parameters
    bits = 2048  # Standard RSA key size
    n = 64       # Larger sequence length for better security
    
    print("NTT-Based Key Exchange Protocol Attack Simulation")
    print("="*50)
    print("\nUsing real-world cryptographic parameters:")
    print(f"- Prime size: {bits} bits")
    print(f"- Sequence length: {n}")
    print(f"- Secret keys: ~{bits} bits")
    
    # Simulate a key exchange
    exchange_result = simulate_key_exchange(bits, n)
    if not exchange_result:
        print("Key exchange simulation failed.")
        return
    
    p, n, w, G, Ga, Gb, true_shared_key = exchange_result
    
    # Print what information Eve has access to
    print("\nEve has intercepted the following public information:")
    print(f"Prime p = {p}")
    print(f"Sequence length n = {n}")
    print(f"Root of unity w = {w}")
    print("Public sequence G = [...]  # Too large to display")
    print("Alice's public value Ga = [...]  # Too large to display")
    print("Bob's public value Gb = [...]  # Too large to display")
    
    # Eve attempts to crack the key
    print("\nEve is attempting to crack the key exchange...")
    eve = Eve(p, n, w, G, Ga, Gb)
    
    # Attack 1: Brute Force (limited to a very small range for demonstration)
    print("\nNote: With real-world parameters, these attacks are computationally infeasible.")
    print("For demonstration, we'll only try a tiny fraction of the possible key space.")
    
    max_attempts = 1000  # Extremely small compared to the actual key space
    success_bf, key_bf, shared_key_bf, time_bf = eve.brute_force_attack(max_attempts=max_attempts)
    
    # Attack 2: Baby-Step Giant-Step (limited to a very small range for demonstration)
    max_range = 1000  # Extremely small compared to the actual key space
    success_bsgs, key_bsgs, shared_key_bsgs, time_bsgs = eve.baby_step_giant_step(max_range=max_range)
    
    # Attack 3: Meet-in-the-Middle (limited to a very small range for demonstration)
    max_range = 1000  # Extremely small compared to the actual key space
    success_mitm, key_mitm, shared_key_mitm, time_mitm = eve.meet_in_the_middle_attack(max_range=max_range)
    
    # Attack 4: Pollards Rho (limited to a very small range for demonstration)
    max_iterations = 1000  # Extremely small compared to the actual key space
    success_rho, key_rho, shared_key_rho, time_rho = eve.pollards_rho_attack(max_iterations=max_iterations)
    
    # Attack 5: Index Calculus (limited to a very small range for demonstration)
    max_relations = 50  # Extremely small compared to the actual key space
    factor_base_size = 10  # Extremely small compared to the actual key space
    success_index, key_index, shared_key_index, time_index = eve.index_calculus_attack(max_relations=max_relations, factor_base_size=factor_base_size)
    
    # Summary
    print("\n=== Summary of Attacks ===")
    print(f"Brute Force: {'Successful' if success_bf else 'Failed'} - Time: {time_bf:.2f}s")
    print(f"Baby-Step Giant-Step: {'Successful' if success_bsgs else 'Failed'} - Time: {time_bsgs:.2f}s")
    print(f"Meet-in-the-Middle: {'Successful' if success_mitm else 'Failed'} - Time: {time_mitm:.2f}s")
    print(f"Pollard's Rho: {'Successful' if success_rho else 'Failed'} - Time: {time_rho:.2f}s")
    print(f"Index Calculus: {'Successful' if success_index else 'Failed'} - Time: {time_index:.2f}s")
    
    # Security analysis
    print("\n=== Security Analysis ===")
    print("With real-world parameters:")
    print(f"- Prime p is {bits} bits ({p.bit_length()} actual bits)")
    print(f"- Secret keys are approximately {bits} bits")
    print(f"- The key space size is approximately 2^{bits}")
    print("\nTo brute force this key space:")
    print(f"- At 1 billion (10^9) attempts per second, it would take approximately")
    print(f"  2^{bits} / 10^9 / (3600*24*365) ≈ 10^{bits * 0.301 - 9 - 7.5:.1f} years")
    print("\nThe Baby-Step Giant-Step and Meet-in-the-Middle attacks reduce this to")
    print(f"approximately 2^{bits//2} operations, but require 2^{bits//2} storage,")
    print(f"which is still completely infeasible.")
    print("\nThe discrete logarithm problem in the NTT domain is believed to be as hard")
    print("as the standard discrete logarithm problem, which is the basis for the")
    print("security of many cryptographic systems including Diffie-Hellman key exchange.")

if __name__ == "__main__":
    main() 
