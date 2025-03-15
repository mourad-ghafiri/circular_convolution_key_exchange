from ntt_cryptosystem import CryptoSystem

def main():
    """
    Demonstration of the NTT-based cryptosystem implementing:
    1. Key generation
    2. Key exchange (similar to Diffie-Hellman but with sequences)
    3. Encryption/decryption
    4. Digital signatures
    
    Mathematical overview:
    - All operations are performed in a finite field GF(p)
    - Uses Number Theoretic Transform (NTT) for efficient convolution operations
    - Security based on the hardness of the discrete logarithm problem in the NTT domain
    """
    
    # Initialize the cryptosystem with smaller parameters for demo
    # For real security, use larger parameters (e.g., bits=2048, seq_length=64)
    print("Initializing NTT-based cryptosystem...")
    crypto = CryptoSystem(bits=512, seq_length=16)
    
    print(f"Prime modulus p: {crypto.p}")
    print(f"Sequence length n: {crypto.n}")
    print(f"Public generator G: {crypto.G}")
    
    # ====== Key Generation ======
    # Each party generates:
    # - Private key: a random integer 'a'
    # - Public key: P = G^{*a} (G convolved with itself 'a' times)
    
    print("\nAlice generates a keypair...")
    alice_private, alice_public = crypto.generate_keypair()
    print(f"Alice's private key: {alice_private}")
    print(f"Alice's public key: {alice_public}")
    
    print("\nBob generates a keypair...")
    bob_private, bob_public = crypto.generate_keypair()
    print(f"Bob's private key: {bob_private}")
    print(f"Bob's public key: {bob_public}")
    
    # ====== Key Exchange ======
    # Mathematical basis:
    # - Alice computes: K_A = Bob_public^{*alice_private} = (G^{*bob_private})^{*alice_private} = G^{*(alice_private*bob_private)}
    # - Bob computes: K_B = Alice_public^{*bob_private} = (G^{*alice_private})^{*bob_private} = G^{*(alice_private*bob_private)}
    # - Both derive the same shared key: K_A = K_B = G^{*(alice_private*bob_private)}
    
    print("\nPerforming key exchange...")
    alice_shared = crypto.share_key(alice_private, bob_public)
    bob_shared = crypto.share_key(bob_private, alice_public)
    
    # Verify shared keys match
    keys_match = alice_shared == bob_shared
    print(f"Shared keys match: {keys_match}")
    if keys_match:
        print(f"Shared key: {alice_shared}")
    
    # ====== Encryption/Decryption ======
    # Mathematical operations:
    # - Encryption: C = M ⊗ K (circular convolution of message with key)
    # - Decryption: M = C ⊘ K (deconvolution, or convolution with inverse)
    # In NTT domain:
    # - NTT(C) = NTT(M) · NTT(K) (point-wise multiplication)
    # - NTT(M) = NTT(C) / NTT(K) (point-wise division)
    
    # Create a sample message (sequence of integers modulo p)
    message = [i % crypto.p for i in range(crypto.n)]
    print(f"\nOriginal message: {message}")
    
    # Alice encrypts a message for Bob using their shared key
    ciphertext = crypto.encrypt(message, alice_shared)
    print(f"Encrypted message: {ciphertext}")
    
    # Bob decrypts the message using the shared key
    decrypted = crypto.decrypt(ciphertext, bob_shared)
    print(f"Decrypted message: {decrypted}")
    print(f"Decryption successful: {message == decrypted}")
    
    # ====== Digital Signature ======
    # Mathematical basis (Schnorr-like signature):
    # 1. Choose random ephemeral key k
    # 2. Compute commitment r = G^{*k}
    # 3. Compute challenge e = H(digest || r)
    # 4. Compute response s = (k + e·a) mod (p-1) where a is private key
    # 
    # Verification:
    # 1. Compute e = H(digest || r)
    # 2. Check if G^s = r ⊗ (P^e)  [where P is the signer's public key]
    
    print("\nTesting digital signature...")
    # Alice signs a message
    signature = crypto.sign(message, alice_private)
    print(f"Alice's signature (r component): {signature[0]}")
    print(f"Alice's signature (s value): {signature[1]}")
    
    # Bob verifies Alice's signature
    # Verification equation: G^s = r ⊗ (Alice_public^e)
    is_valid = crypto.verify(message, signature, alice_public)
    print(f"Signature verification result: {is_valid}")
    
    # Try with tampered message
    # This should fail verification since the signature is bound to the original message
    tampered_message = message.copy()
    if len(tampered_message) > 0:
        tampered_message[0] = (tampered_message[0] + 1) % crypto.p
    
    is_valid_tampered = crypto.verify(tampered_message, signature, alice_public)
    print(f"Tampered message verification result: {is_valid_tampered}")

if __name__ == "__main__":
    main() 
