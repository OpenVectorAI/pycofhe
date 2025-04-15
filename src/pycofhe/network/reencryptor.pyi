from __future__ import annotations

from typing import Tuple, TypeVar, Generic

from pycofhe.cryptosystems.cpu_cryptosystem_core import (
    CPUCryptoSystemCipherText,
    CPUCryptoSystemPartialDecryptionResult,
    CPUCryptoSystemPlainText,
    CPUCryptoSystemPublicKey,
    CPUCryptoSystemSecretKey,
    CPUCryptoSystemSecretKeyShare,
)
from pycofhe.cryptosystems.cryptosystem import (
    SecretKey,
    SecretKeyShare,
    PublicKey,
    PlainText,
    CipherText,
    PartialDecryptionResult,
)
from pycofhe.tensor.tensor_core import GenericTensor

PKCEncryptor = TypeVar("PKCEncryptor")

class ReencryptorKeyPair(Generic[PKCEncryptor]):
    """Reencryptor key pair for a given PKCEncryptor."""

    pass

class Reencryptor(
    Generic[
        PKCEncryptor,
        SecretKey,
        SecretKeyShare,
        PublicKey,
        PlainText,
        CipherText,
        PartialDecryptionResult,
    ]
):
    """Reencryptor for a given PKCEncryptor and cryptosystem."""

    def decrypt(
        self,
        reencryted_partial_decryption_result: bytes,
        ct: CipherText,
        serialized_private_key: bytes,
    ) -> PlainText:
        """Decrypts the given ciphertext and reeencrypted partial decryption results using the provided reencryption key."""
        pass

    def decrypt_tensor(
        self,
        reencryted_partial_decryption_result: bytes,
        ct: GenericTensor[CipherText],
        serialized_private_key: bytes,
    ) -> GenericTensor[PlainText]:
        """Decrypts the given ciphertext tensor and reeencrypted partial decryption results using the provided reencryption key."""
        pass

    def generate_serialized_key_pair(self) -> Tuple[bytes, bytes]:
        """Generates a serialized reencryption key pair."""
        pass

class RSAPKCEncryptor:
    """RSA PKC Encryptor."""

    pass

class RSAPKCEncryptorReencryptionKeyPair(ReencryptorKeyPair[RSAPKCEncryptor]):
    """RSA PKC Encryptor Reencryption Key Pair."""

    pass

class RSAPKCEncryptorReencryptor(
    Reencryptor[
        RSAPKCEncryptor,
        SecretKey,
        SecretKeyShare,
        PublicKey,
        PlainText,
        CipherText,
        PartialDecryptionResult,
    ]
):
    """RSA PKC Encryptor Reencryption."""

    pass

class RSAPKCEncryptorCPUCryptoSystemReencryptor(
    Reencryptor[
        RSAPKCEncryptor,
        CPUCryptoSystemSecretKey,
        CPUCryptoSystemSecretKeyShare,
        CPUCryptoSystemPublicKey,
        CPUCryptoSystemPlainText,
        CPUCryptoSystemCipherText,
        CPUCryptoSystemPartialDecryptionResult,
    ]
):
    """RSA PKC Encryptor CPU CryptoSystem."""

    pass
