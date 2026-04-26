import random
import sys
from typing import List, Union, Any

# Try to import tenseal, otherwise use a mock
try:
    import tenseal as ts
    HAS_TENSEAL = True
except ImportError:
    HAS_TENSEAL = False
    print("[ShieldAI Info]: TenSEAL library not found. Using MockHE wrapper for demonstration.")

class HomomorphicEngine:
    """
    A wrapper around TenSEAL to handle Homomorphic Encryption operations.
    If TenSEAL is missing, it mocks the behavior (store cleartext, return 'EncryptedVector' object)
    so the pipeline logic can be verified.
    """

    def __init__(self):
        if HAS_TENSEAL:
            # Setup TenSEAL context for CKKS (Approximate numbers, good for vectors)
            self.context = ts.context(
                ts.SCHEME_TYPE.CKKS,
                poly_modulus_degree=8192,
                coeff_mod_bit_sizes=[60, 40, 40, 60]
            )
            self.context.global_scale = 2**40
            self.context.generate_galois_keys()
        else:
            self.context = None

    def encrypt_vector(self, vector: List[float]) -> Any:
        """Encrypts a list of floats."""
        if HAS_TENSEAL:
            return ts.ckks_vector(self.context, vector)
        else:
            return MockEncryptedVector(vector)

    def decrypt_vector(self, encrypted_vector: Any) -> List[float]:
        """Decrypts an encrypted vector."""
        if HAS_TENSEAL:
            return encrypted_vector.decrypt()
        else:
            return encrypted_vector.decrypt()

class MockEncryptedVector:
    """
    Simulates an encrypted vector for testing logic without the crypto library.
    It holds the cleartext but behaves like a black box to the 'Server'.
    """
    def __init__(self, data: List[float]):
        self._data = data
        self._is_encrypted = True

    def __add__(self, other):
        # Homomorphic Addition
        if isinstance(other, MockEncryptedVector):
            new_data = [x + y for x, y in zip(self._data, other._data)]
        elif isinstance(other, (int, float)):
            new_data = [x + other for x in self._data]
        else: # List
            new_data = [x + y for x, y in zip(self._data, other)]
        return MockEncryptedVector(new_data)

    def __mul__(self, other):
        # Homomorphic Multiplication
        if isinstance(other, MockEncryptedVector):
             new_data = [x * y for x, y in zip(self._data, other._data)]
        elif isinstance(other, (int, float)):
            new_data = [x * other for x in self._data]
        else: # List
            new_data = [x * y for x, y in zip(self._data, other)]
        return MockEncryptedVector(new_data)
        
    def dot(self, other):
        # Homomorphic Dot Product
        if isinstance(other, list):
             result = sum(x * y for x, y in zip(self._data, other))
             return MockEncryptedVector([result])
        return NotImplemented

    def decrypt(self):
        # Client-side decryption
        return self._data
