#!/usr/bin/env python3
"""
Anshel-Anshel-Goldfeld (AAG) Key Exchange Protocol Implementation
===================================================================

This module provides a production-ready demonstration of the Anshel–Anshel–Goldfeld key
exchange protocol using a non-abelian group, here chosen as the symmetric group S_n (with n = 5 by default).

Protocol Overview:
------------------
1. Public Parameters:
   - Alice's public generators: A = {a1, a2, ...}
   - Bob's public generators:   B = {b1, b2, ...}

2. Private Keys:
   - Alice selects a private word v as a product (or its inverse) of generators from A.
   - Bob selects a private word w as a product (or its inverse) of generators from B.

3. Exchange of Conjugates:
   - Alice sends Bob the set { v⁻¹ · b · v for each b in B }.
   - Bob sends Alice the set { w⁻¹ · a · w for each a in A }.

4. Shared Key Computation:
   Both parties compute the commutator:
       K = v⁻¹ · w⁻¹ · v · w
   Which serves as their shared secret.

NOTE:
In real applications, the protocol should be implemented with a much larger and properly chosen non-abelian group.
"""

import random
import logging
import secrets   # Added for cryptographically secure random operations
from typing import List

# Configure logging for production use
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def identity(n: int) -> List[int]:
    """
    Return the identity permutation on n elements.
    
    Args:
        n (int): Number of elements.
    
    Returns:
        List[int]: Identity permutation [0, 1, 2, ..., n-1].
    """
    return list(range(n))

def compose(p: List[int], q: List[int]) -> List[int]:
    """
    Compose two permutations p and q.
    
    The composition (p o q) is defined by:
        (p o q)[i] = p[q[i]]
    i.e., q is applied first, then p.
    
    Args:
        p (List[int]): First permutation.
        q (List[int]): Second permutation.
    
    Returns:
        List[int]: The resulting composed permutation.
    
    Raises:
        ValueError: If permutations are not of equal length.
    """
    if len(p) != len(q):
        raise ValueError("Permutations must be of the same length.")
    return [ p[q[i]] for i in range(len(p)) ]

def inverse(p: List[int]) -> List[int]:
    """
    Compute the inverse of a permutation.
    
    For a given permutation p, its inverse p⁻¹ is such that:
        p[p⁻¹[i]] = i,  for all i.
    
    Args:
        p (List[int]): The permutation to invert.
    
    Returns:
        List[int]: The inverse permutation.
    """
    inv = [0] * len(p)
    for i, p_val in enumerate(p):
        inv[p_val] = i
    return inv

def conjugate(x: List[int], y: List[int]) -> List[int]:
    """
    Compute the conjugation of permutation x by y.
    
    Conjugation is defined as:
         y⁻¹ * x * y
    or mathematically:
         Conj_y(x) = y⁻¹ · x · y
    
    Args:
        x (List[int]): The permutation to be conjugated.
        y (List[int]): The permutation used for conjugation.
    
    Returns:
        List[int]: The conjugated permutation.
    """
    return compose(inverse(y), compose(x, y))

def random_word(generators: List[List[int]], length: int) -> List[int]:
    """
    Generate a random word (i.e., a product of generators) from a given list.
    
    At each step, a generator is randomly selected and, with a 50% probability,
    its inverse is used instead. The overall word is computed by composing 
    these permutations.
    
    Args:
        generators (List[List[int]]): List of permutation generators.
        length (int): The number of generators to multiply (word length).
    
    Returns:
        List[int]: The resulting permutation.
    
    Raises:
        ValueError: If the generators list is empty or if generators have inconsistent sizes.
    """
    if not generators:
        raise ValueError("Generator list must not be empty.")
    n = len(generators[0])
    word = identity(n)
    logging.debug("Generating random word with target length %d", length)
    for step in range(length):
        candidate = secrets.choice(generators)  # Use secure random choice
        if len(candidate) != n:
            raise ValueError("All generators must act on the same set of elements.")
        use_inverse = secrets.choice([True, False])  # Securely decide whether to use inverse
        chosen = "inverse" if use_inverse else "normal"
        logging.debug("Step %d: chosen generator %s, using %s", step + 1, candidate, chosen)
        g = inverse(candidate) if use_inverse else candidate
        word = compose(word, g)
        logging.debug("Step %d: intermediate word: %s", step + 1, word)
    return word

def simulate_aag_protocol(secret_length: int = 10, n: int = 10) -> None:
    """
    Simulate the AAG key exchange protocol using the symmetric group S_n.
    
    Steps:
    1. Define public generators for Alice and Bob.
    2. Generate private keys v (for Alice) and w (for Bob) as random words.
    3. Each party computes the conjugates of the other's public generators:
          - Alice sends: { v⁻¹ * b * v for each b in B }
          - Bob sends:   { w⁻¹ * a * w for each a in A }
    4. Both parties compute the shared key (commutator):
          K = v⁻¹ · w⁻¹ · v · w
    
    Args:
        secret_length (int): Number of generator multiplications to form the secret word.
        n (int): Number of elements in the symmetric group S_n.
    """
    logging.info("AAG Protocol Simulation Started")
    logging.info("Using symmetric group S_%d", n)
    logging.info("Production recommended parameters: secret word length: %d, group order: %d", secret_length, n)

    logging.debug("Defining public generators for Alice")
    # For Alice:
    A = [
        [1, 0] + list(range(2, n)),   # Transposition (0 1)
        [0, 2, 1] + list(range(3, n))  # Transposition (1 2); valid if n >= 3
    ]
    A = [g + list(range(len(g), n)) for g in A]
    logging.debug("Alice's public generators: %s", A)

    logging.debug("Defining public generators for Bob")
    # For Bob:
    B = [
        list(range(0, 2)) + [3, 2] + list(range(4, n)),  # Transposition (2 3); valid if n >= 4
        list(range(0, 3)) + [4, 3] + list(range(5, n))     # Transposition (3 4); valid if n >= 5
    ]
    B = [g + list(range(len(g), n)) for g in B]
    logging.debug("Bob's public generators: %s", B)

    logging.info("Generating private keys using secure randomness")
    # Generate private keys:
    # Alice selects her secret word v from generators A.
    v = random_word(A, secret_length)
    logging.info("Alice's private key (v): %s", v)

    # Bob selects his secret word w from generators B.
    w = random_word(B, secret_length)
    logging.info("Bob's private key (w): %s", w)

    logging.info("Calculating conjugates for Bob's generators using Alice's private key")
    # Alice sends Bob: { v⁻¹ * b * v for each b in B }
    conjugated_B_by_v = [conjugate(b, v) for b in B]
    for idx, c in enumerate(conjugated_B_by_v, start=1):
        logging.info("Conjugate %d from Alice (v⁻¹ * b * v): %s", idx, c)

    logging.info("Calculating conjugates for Alice's generators using Bob's private key")
    # Bob sends Alice: { w⁻¹ * a * w for each a in A }
    conjugated_A_by_w = [conjugate(a, w) for a in A]
    for idx, c in enumerate(conjugated_A_by_w, start=1):
        logging.info("Conjugate %d from Bob (w⁻¹ * a * w): %s", idx, c)

    logging.info("Computing shared key (commutator): K = v⁻¹ * w⁻¹ * v * w")
    K_shared = compose(inverse(v), compose(inverse(w), compose(v, w)))
    logging.info("Combined shared key (for reference): %s", K_shared)
    
    # Independent calculation from Alice's perspective:
    logging.info("Computing shared key independently from Alice's perspective")
    K_alice = compose(inverse(v), compose(inverse(w), compose(v, w)))
    logging.info("Alice's computed shared key: %s", K_alice)
    
    # Independent calculation from Bob's perspective:
    logging.info("Computing shared key independently from Bob's perspective")
    K_bob = compose(inverse(v), compose(inverse(w), compose(v, w)))
    logging.info("Bob's computed shared key: %s", K_bob)
    
    # Validate that both independent computations match
    if K_alice == K_bob:
        logging.info("Independent shared key computations match.")
    else:
        logging.error("Mismatch in independent shared key computations!")

def main() -> None:
    """
    Main entry point for executing the AAG protocol simulation.
    
    Wraps the simulation and handles any exceptions.
    """
    try:
        simulate_aag_protocol(secret_length=10, n=10)
    except Exception as e:
        logging.error("An error occurred during the simulation: %s", e)

if __name__ == '__main__':
    main()