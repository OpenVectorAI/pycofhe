from __future__ import annotations

from pycofhe.cryptosystems.cryptosystem import CryptoSystem

# pylint: disable=unused-argument,unnecessary-ellipsis

class CPUCryptoSystemSecretKey:
    """Represents a secret key."""

    pass

class CPUCryptoSystemSecretKeyShare:
    """Represents a share of a secret key."""

    pass

CPUCryptoSystemPlainText = CPUCryptoSystemSecretKeyShare
"""Alias for SecretKeyShare representing plaintext."""

class CPUCryptoSystemPublicKey:
    """Represents a public key."""

    pass

class CPUCryptoSystemCipherText:
    """Represents a ciphertext."""

    pass

class CPUCryptoSystemPartialDecryptionResult:
    """Represents a partial decryption result."""

    pass

class CPUCryptoSystem(
    CryptoSystem[
        CPUCryptoSystemSecretKey,
        CPUCryptoSystemSecretKeyShare,
        CPUCryptoSystemPublicKey,
        CPUCryptoSystemPlainText,
        CPUCryptoSystemCipherText,
        CPUCryptoSystemPartialDecryptionResult
    ]
):
    """Represents a CPU-based cryptosystem."""

    pass
