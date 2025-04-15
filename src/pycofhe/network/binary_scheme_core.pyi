"""Typing stubs for the binary scheme core functions."""

from __future__ import annotations

from typing import List, overload

from pycofhe.cryptosystems.cryptosystem import (
    CryptoSystem,
    SecretKey,
    SecretKeyShare,
    PublicKey,
    PlainText,
    CipherText,
    PartialDecryptionResult
)
from pycofhe.network.reencryptor import PKCEncryptor
from pycofhe.network.network_core import ClientNode

# pylint: disable=unused-argument,unnecessary-ellipsis

def encrypt_bit(
    cs: CryptoSystem[
        SecretKey,
        SecretKeyShare,
        PublicKey,
        PlainText,
        CipherText,
        PartialDecryptionResult
    ],
    pk: PublicKey,
    plaintext: int,
) -> CipherText:
    """Encrypt the given plaintext using binary encoding scheme.

    Args:
        cs (CryptoSystem): The cryptosystem to use.
        pk (PublicKey): The public key to use.
        plaintext (int): The plaintext bit to encrypt.

    Returns:
        Ciphertext: The encrypted ciphertext, in binary encoding.
    """
    ...

def decrypt_bit(
    cs: ClientNode[
        SecretKey,
        SecretKeyShare,
        PublicKey,
        PlainText,
        CipherText,
        PartialDecryptionResult,
        PKCEncryptor,
    ],
    ciphertext: CipherText,
) -> int:
    """Decrypt the given ciphertext using binary encoding scheme.

    Args:
        cs (ClientNode): The cryptosystem to use.
        ciphertext (Ciphertext): The ciphertext bit to decrypt.

    Returns:
        int: The decrypted bit.
    """
    ...

def encrypt_bitwise(
    cs: CryptoSystem[
        SecretKey,
        SecretKeyShare,
        PublicKey,
        PlainText,
        CipherText,
        PartialDecryptionResult,
    ],
    pk: PublicKey,
    plaintext: int,
) -> List[CipherText]:
    """Encrypt the given plaintext using binary encoding scheme.

    Args:
        cs (CryptoSystem): The cryptosystem to use.
        pk (PublicKey): The public key to use.
        plaintext (int): The plaintext to encrypt.

    Returns:
        List[Ciphertext]: The encrypted ciphertext, in binary encoding.
    """
    ...

def decrypt_bitwise(
    cs: ClientNode[
        SecretKey,
        SecretKeyShare,
        PublicKey,
        PlainText,
        CipherText,
        PartialDecryptionResult,
        PKCEncryptor,
    ],
    ciphertext: List[CipherText],
) -> int:
    """Decrypt the given ciphertext using binary encoding scheme.

    Args:
        cs (ClientNode): The cryptosystem to use.
        ciphertext (List[Ciphertext]): The ciphertext to decrypt.

    Returns:
        int: The decrypted plaintext.
    """
    ...

@overload
def homomorphic_not(
    client_node: ClientNode[
        SecretKey,
        SecretKeyShare,
        PublicKey,
        PlainText,
        CipherText,
        PartialDecryptionResult,
        PKCEncryptor,
    ],
    ct: CipherText,
) -> CipherText:
    """Perform homomorphic NOT operation on the given ciphertext.

    Args:
        client_node (ClientNode): The client node.
        ct (Ciphertext): The ciphertext.

    Returns:
        Ciphertext: The result of the operation.
    """
    ...

@overload
def homomorphic_not(
    client_node: ClientNode[
        SecretKey,
        SecretKeyShare,
        PublicKey,
        PlainText,
        CipherText,
        PartialDecryptionResult,
        PKCEncryptor,
    ],
    ct: List[CipherText],
) -> List[CipherText]:
    """Perform homomorphic NOT operation on the given ciphertext.

    Args:
        client_node (ClientNode): The client node.
        ct (List[CipherText]): The ciphertext.

    Returns:
        List[CipherText]: The result of the operation.
    """
    ...

@overload
def homomorphic_and(
    client_node: ClientNode[
        SecretKey,
        SecretKeyShare,
        PublicKey,
        PlainText,
        CipherText,
        PartialDecryptionResult,
        PKCEncryptor,
    ],
    ct1: List[CipherText],
    ct2: List[CipherText],
) -> List[CipherText]:
    """Perform homomorphic AND operation on the given ciphertexts.

    Args:
        client_node (ClientNode): The client node.
        ct1 (List[CipherText]): The first ciphertext.
        ct2 (List[CipherText]): The second ciphertext.

    Returns:
        List[CipherText]: The result of the operation.
    """
    ...

@overload
def homomorphic_and(
    client_node: ClientNode[
        SecretKey,
        SecretKeyShare,
        PublicKey,
        PlainText,
        CipherText,
        PartialDecryptionResult,
        PKCEncryptor,
    ],
    ct1: CipherText,
    ct2: CipherText,
) -> CipherText:
    """Perform homomorphic AND operation on the given ciphertexts.

    Args:
        client_node (ClientNode): The client node.
        ct1 (Ciphertext): The first ciphertext.
        ct2 (Ciphertext): The second ciphertext.

    Returns:
        Ciphertext: The result of the operation.
    """
    ...

@overload
def homomorphic_or(
    client_node: ClientNode[
        SecretKey,
        SecretKeyShare,
        PublicKey,
        PlainText,
        CipherText,
        PartialDecryptionResult,
        PKCEncryptor,
    ],
    ct1: CipherText,
    ct2: CipherText,
) -> CipherText:
    """Perform homomorphic OR operation on the given ciphertexts.

    Args:
        client_node (ClientNode): The client node.
        ct1 (Ciphertext): The first ciphertext.
        ct2 (Ciphertext): The second ciphertext.

    Returns:
        Ciphertext: The result of the operation.
    """
    ...

@overload
def homomorphic_or(
    client_node: ClientNode[
        SecretKey,
        SecretKeyShare,
        PublicKey,
        PlainText,
        CipherText,
        PartialDecryptionResult,
        PKCEncryptor,
    ],
    ct1: List[CipherText],
    ct2: List[CipherText],
) -> List[CipherText]:
    """Perform homomorphic OR operation on the given ciphertexts.

    Args:
        client_node (ClientNode): The client node.
        ct1 (List[CipherText]): The first ciphertext.
        ct2 (List[CipherText]): The second ciphertext.

    Returns:
        List[CipherText]: The result of the operation.
    """
    ...

@overload
def homomorphic_xor(
    client_node: ClientNode[
        SecretKey,
        SecretKeyShare,
        PublicKey,
        PlainText,
        CipherText,
        PartialDecryptionResult,
        PKCEncryptor,
    ],
    ct1: CipherText,
    ct2: CipherText,
) -> CipherText:
    """Perform homomorphic XOR operation on the given ciphertexts.

    Args:
        client_node (ClientNode): The client node.
        ct1 (Ciphertext): The first ciphertext.
        ct2 (Ciphertext): The second ciphertext.

    Returns:
        Ciphertext: The result of the operation.
    """
    ...

@overload
def homomorphic_xor(
    client_node: ClientNode[
        SecretKey,
        SecretKeyShare,
        PublicKey,
        PlainText,
        CipherText,
        PartialDecryptionResult,
        PKCEncryptor,
    ],
    ct1: List[CipherText],
    ct2: List[CipherText],
) -> List[CipherText]:
    """Perform homomorphic XOR operation on the given ciphertexts.

    Args:
        client_node (ClientNode): The client node.
        ct1 (List[CipherText]): The first ciphertext.
        ct2 (List[CipherText]): The second ciphertext.

    Returns:
        List[CipherText]: The result of the operation.
    """
    ...

def homomorphic_nand(
    client_node: ClientNode[
        SecretKey,
        SecretKeyShare,
        PublicKey,
        PlainText,
        CipherText,
        PartialDecryptionResult,
        PKCEncryptor,
    ],
    ct1: CipherText,
    ct2: CipherText,
) -> CipherText:
    """Perform homomorphic NAND operation on the given ciphertexts.

    Args:
        client_node (ClientNode): The client node.
        ct1 (Ciphertext): The first ciphertext.
        ct2 (Ciphertext): The second ciphertext.

    Returns:
        Ciphertext: The result of the operation.
    """
    ...

def homomorphic_add(
    client_node: ClientNode[
        SecretKey,
        SecretKeyShare,
        PublicKey,
        PlainText,
        CipherText,
        PartialDecryptionResult,
        PKCEncryptor,
    ],
    ct1: List[CipherText],
    ct2: List[CipherText],
) -> List[CipherText]:
    """Perform homomorphic ADD operation on the given ciphertexts.

    Args:
        client_node (ClientNode): The client node.
        ct1 (List[CipherText]): The first ciphertext.
        ct2 (List[CipherText]): The second ciphertext.

    Returns:
        List[CipherText]: The result of the operation.
    """
    ...

def homomorphic_sub(
    client_node: ClientNode[
        SecretKey,
        SecretKeyShare,
        PublicKey,
        PlainText,
        CipherText,
        PartialDecryptionResult,
        PKCEncryptor,
    ],
    ct1: List[CipherText],
    ct2: List[CipherText],
) -> List[CipherText]:
    """Perform homomorphic SUB operation on the given ciphertexts.

    Args:
        client_node (ClientNode): The client node.
        ct1 (List[CipherText]): The first ciphertext.
        ct2 (List[CipherText]): The second ciphertext.

    Returns:
        List[CipherText]: The result of the operation.
    """
    ...

def homomorphic_lt(
    client_node: ClientNode[
        SecretKey,
        SecretKeyShare,
        PublicKey,
        PlainText,
        CipherText,
        PartialDecryptionResult,
        PKCEncryptor,
    ],
    ct1: List[CipherText],
    ct2: List[CipherText],
) -> CipherText:
    """Perform homomorphic LT operation on the given ciphertexts.

    Args:
        client_node (ClientNode): The client node.
        ct1 (List[CipherText]): The first ciphertext.
        ct2 (List[CipherText]): The second ciphertext.

    Returns:
        CipherText: The result of the operation.
    """
    ...

def homomorphic_eq(
    client_node: ClientNode[
        SecretKey,
        SecretKeyShare,
        PublicKey,
        PlainText,
        CipherText,
        PartialDecryptionResult,
        PKCEncryptor,
    ],
    ct1: List[CipherText],
    ct2: List[CipherText],
) -> CipherText:
    """Perform homomorphic EQ operation on the given ciphertexts.

    Args:
        client_node (ClientNode): The client node.
        ct1 (List[CipherText]): The first ciphertext.
        ct2 (List[CipherText]): The second ciphertext.

    Returns:
        CipherText: The result of the operation.
    """
    ...

def homomorphic_gt(
    client_node: ClientNode[
        SecretKey,
        SecretKeyShare,
        PublicKey,
        PlainText,
        CipherText,
        PartialDecryptionResult,
        PKCEncryptor,
    ],
    ct1: List[CipherText],
    ct2: List[CipherText],
) -> CipherText:
    """Perform homomorphic GT operation on the given ciphertexts.

    Args:
        client_node (ClientNode): The client node.
        ct1 (List[CipherText]): The first ciphertext.
        ct2 (List[CipherText]): The second ciphertext.

    Returns:
        CipherText: The result of the operation.
    """
    ...

def serialize_bit(
    cs: CryptoSystem[
        SecretKey,
        SecretKeyShare,
        PublicKey,
        PlainText,
        CipherText,
        PartialDecryptionResult,
    ],
    ciphertext: CipherText,
) -> bytes:
    """Serialize the given ciphertext using binary encoding scheme.

    Args:
        cs (CryptoSystem): The cryptosystem to use.
        ciphertext (Ciphertext): The ciphertext to serialize.

    Returns:
        bytes: The serialized ciphertext.
    """
    ...

def deserialize_bit(
    cs: CryptoSystem[
        SecretKey,
        SecretKeyShare,
        PublicKey,
        PlainText,
        CipherText,
        PartialDecryptionResult,
    ],
    serialized: bytes,
) -> CipherText:
    """Deserialize the given ciphertext using binary encoding scheme.

    Args:
        cs (CryptoSystem): The cryptosystem to use.
        serialized (bytes): The serialized ciphertext.

    Returns:
        Ciphertext: The deserialized ciphertext.
    """
    ...

def serialize_bitwise(
    cs: CryptoSystem[
        SecretKey,
        SecretKeyShare,
        PublicKey,
        PlainText,
        CipherText,
        PartialDecryptionResult,
    ],
    ciphertext: List[CipherText],
) -> bytes:
    """Serialize the given ciphertext using binary encoding scheme.

    Args:
        cs (CryptoSystem): The cryptosystem to use.
        ciphertext (List[CipherText]): The ciphertext to serialize.

    Returns:
        bytes: The serialized ciphertexts.
    """
    ...

def deserialize_bitwise(
    cs: CryptoSystem[
        SecretKey,
        SecretKeyShare,
        PublicKey,
        PlainText,
        CipherText,
        PartialDecryptionResult
    ],
    serialized: bytes,
) -> List[CipherText]:
    """Deserialize the given ciphertext using binary encoding scheme.

    Args:
        cs (CryptoSystem): The cryptosystem to use.
        serialized (bytes): The serialized ciphertext.

    Returns:
        List[CipherText]: The deserialized ciphertexts.
    """
    ...
