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
        CPUCryptoSystemPartialDecryptionResult,
    ]
):
    """Represents a CPU-based cryptosystem."""

    def __init__(
        self,
        security_level: int,
        k: int,
        N: str = "",
        compact: bool = False,
    ) -> None:
        """Initialize the CPUCryptoSystem.

        Args:
            security_level (int): The security level in bits.
            k (int): The message space size (2^k).
            N (str): The N value as a string. Defaults to None.
            compact (bool): Whether to use compact mode. Defaults to False.
        """
        ...

    @property
    def k(self) -> int:
        """Get the message space size (2^k).

        Returns:
            int: The message space size.
        """
        pass

    @property
    def exponent_bound(self) -> int:
        """Get the exponent bound.

        Returns:
            int: The exponent bound.
        """
        pass

    @property
    def N(self) -> int:
        """Get the N value.

        Returns:
            int: The N value.
        """
        pass
