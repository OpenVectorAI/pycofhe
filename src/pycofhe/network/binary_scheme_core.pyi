"""Typing stubs for the binary scheme core functions."""

from __future__ import annotations

from typing import List, overload

from pycofhe.cpu_cryptosystem import CPUCryptoSystem, PublicKey, CipherText
from pycofhe.network import CPUCryptoSystemClientNode

# pylint: disable=unused-argument,unnecessary-ellipsis

def encrypt_bit(
    cs: CPUCryptoSystem,
    pk: PublicKey,
    plaintext: int,
) -> CipherText:
    """Encrypt the given plaintext using binary encoding scheme.

    Args:
        cs (CPUCryptoSystem): The cryptosystem to use.
        pk (PublicKey): The public key to use.
        plaintext (int): The plaintext bit to encrypt.

    Returns:
        Ciphertext: The encrypted ciphertext, in binary encoding.
    """
    ...

def decrypt_bit(
    cs: CPUCryptoSystemClientNode,
    ciphertext: CipherText,
) -> int:
    """Decrypt the given ciphertext using binary encoding scheme.

    Args:
        cs (CPUCryptoSystemClientNode): The cryptosystem to use.
        ciphertext (Ciphertext): The ciphertext bit to decrypt.

    Returns:
        int: The decrypted bit.
    """
    ...

def encrypt_bitwise(
    cs: CPUCryptoSystem,
    pk: PublicKey,
    plaintext: int,
) -> List[CipherText]:
    """Encrypt the given plaintext using binary encoding scheme.

    Args:
        cs (CPUCryptoSystem): The cryptosystem to use.
        pk (PublicKey): The public key to use.
        plaintext (int): The plaintext to encrypt.

    Returns:
        List[Ciphertext]: The encrypted ciphertext, in binary encoding.
    """
    ...

def decrypt_bitwise(
    cs: CPUCryptoSystemClientNode,
    ciphertext: List[CipherText],
) -> int:
    """Decrypt the given ciphertext using binary encoding scheme.

    Args:
        cs (CPUCryptoSystemClientNode): The cryptosystem to use.
        ciphertext (List[Ciphertext]): The ciphertext to decrypt.

    Returns:
        int: The decrypted plaintext.
    """
    ...

@overload
def homomorphic_not(
    client_node: CPUCryptoSystemClientNode, ct: CipherText
) -> CipherText:
    """Perform homomorphic NOT operation on the given ciphertext.

    Args:
        client_node (CPUCryptoSystemClientNode): The client node.
        ct (Ciphertext): The ciphertext.

    Returns:
        Ciphertext: The result of the operation.
    """
    ...

@overload
def homomorphic_not(
    client_node: CPUCryptoSystemClientNode,
    ct: List[CipherText],
) -> List[CipherText]:
    """Perform homomorphic NOT operation on the given ciphertext.

    Args:
        client_node (CPUCryptoSystemClientNode): The client node.
        ct (List[CipherText]): The ciphertext.

    Returns:
        List[CipherText]: The result of the operation.
    """
    ...

@overload
def homomorphic_and(
    client_node: CPUCryptoSystemClientNode,
    ct1: List[CipherText],
    ct2: List[CipherText],
) -> List[CipherText]:
    """Perform homomorphic AND operation on the given ciphertexts.

    Args:
        client_node (CPUCryptoSystemClientNode): The client node.
        ct1 (List[CipherText]): The first ciphertext.
        ct2 (List[CipherText]): The second ciphertext.

    Returns:
        List[CipherText]: The result of the operation.
    """
    ...

@overload
def homomorphic_and(
    client_node: CPUCryptoSystemClientNode,
    ct1: CipherText,
    ct2: CipherText,
) -> CipherText:
    """Perform homomorphic AND operation on the given ciphertexts.

    Args:
        client_node (CPUCryptoSystemClientNode): The client node.
        ct1 (Ciphertext): The first ciphertext.
        ct2 (Ciphertext): The second ciphertext.

    Returns:
        Ciphertext: The result of the operation.
    """
    ...

@overload
def homomorphic_or(
    client_node: CPUCryptoSystemClientNode,
    ct1: CipherText,
    ct2: CipherText,
) -> CipherText:
    """Perform homomorphic OR operation on the given ciphertexts.

    Args:
        client_node (CPUCryptoSystemClientNode): The client node.
        ct1 (Ciphertext): The first ciphertext.
        ct2 (Ciphertext): The second ciphertext.

    Returns:
        Ciphertext: The result of the operation.
    """
    ...

@overload
def homomorphic_or(
    client_node: CPUCryptoSystemClientNode,
    ct1: List[CipherText],
    ct2: List[CipherText],
) -> List[CipherText]:
    """Perform homomorphic OR operation on the given ciphertexts.

    Args:
        client_node (CPUCryptoSystemClientNode): The client node.
        ct1 (List[CipherText]): The first ciphertext.
        ct2 (List[CipherText]): The second ciphertext.

    Returns:
        List[CipherText]: The result of the operation.
    """
    ...

@overload
def homomorphic_xor(
    client_node: CPUCryptoSystemClientNode,
    ct1: CipherText,
    ct2: CipherText,
) -> CipherText:
    """Perform homomorphic XOR operation on the given ciphertexts.

    Args:
        client_node (CPUCryptoSystemClientNode): The client node.
        ct1 (Ciphertext): The first ciphertext.
        ct2 (Ciphertext): The second ciphertext.

    Returns:
        Ciphertext: The result of the operation.
    """
    ...

@overload
def homomorphic_xor(
    client_node: CPUCryptoSystemClientNode,
    ct1: List[CipherText],
    ct2: List[CipherText],
) -> List[CipherText]:
    """Perform homomorphic XOR operation on the given ciphertexts.

    Args:
        client_node (CPUCryptoSystemClientNode): The client node.
        ct1 (List[CipherText]): The first ciphertext.
        ct2 (List[CipherText]): The second ciphertext.

    Returns:
        List[CipherText]: The result of the operation.
    """
    ...

def homomorphic_nand(
    client_node: CPUCryptoSystemClientNode,
    ct1: CipherText,
    ct2: CipherText,
) -> CipherText:
    """Perform homomorphic NAND operation on the given ciphertexts.

    Args:
        client_node (CPUCryptoSystemClientNode): The client node.
        ct1 (Ciphertext): The first ciphertext.
        ct2 (Ciphertext): The second ciphertext.

    Returns:
        Ciphertext: The result of the operation.
    """
    ...

def homomorphic_add(
    client_node: CPUCryptoSystemClientNode,
    ct1: List[CipherText],
    ct2: List[CipherText],
) -> List[CipherText]:
    """Perform homomorphic ADD operation on the given ciphertexts.

    Args:
        client_node (CPUCryptoSystemClientNode): The client node.
        ct1 (List[CipherText]): The first ciphertext.
        ct2 (List[CipherText]): The second ciphertext.

    Returns:
        List[CipherText]: The result of the operation.
    """
    ...

def homomorphic_sub(
    client_node: CPUCryptoSystemClientNode,
    ct1: List[CipherText],
    ct2: List[CipherText],
) -> List[CipherText]:
    """Perform homomorphic SUB operation on the given ciphertexts.

    Args:
        client_node (CPUCryptoSystemClientNode): The client node.
        ct1 (List[CipherText]): The first ciphertext.
        ct2 (List[CipherText]): The second ciphertext.

    Returns:
        List[CipherText]: The result of the operation.
    """
    ...

def homomorphic_lt(
    client_node: CPUCryptoSystemClientNode,
    ct1: List[CipherText],
    ct2: List[CipherText],
) -> CipherText:
    """Perform homomorphic LT operation on the given ciphertexts.

    Args:
        client_node (CPUCryptoSystemClientNode): The client node.
        ct1 (List[CipherText]): The first ciphertext.
        ct2 (List[CipherText]): The second ciphertext.

    Returns:
        CipherText: The result of the operation.
    """
    ...

def homomorphic_eq(
    client_node: CPUCryptoSystemClientNode,
    ct1: List[CipherText],
    ct2: List[CipherText],
) -> CipherText:
    """Perform homomorphic EQ operation on the given ciphertexts.

    Args:
        client_node (CPUCryptoSystemClientNode): The client node.
        ct1 (List[CipherText]): The first ciphertext.
        ct2 (List[CipherText]): The second ciphertext.

    Returns:
        CipherText: The result of the operation.
    """
    ...

def homomorphic_gt(
    client_node: CPUCryptoSystemClientNode,
    ct1: List[CipherText],
    ct2: List[CipherText],
) -> CipherText:
    """Perform homomorphic GT operation on the given ciphertexts.

    Args:
        client_node (CPUCryptoSystemClientNode): The client node.
        ct1 (List[CipherText]): The first ciphertext.
        ct2 (List[CipherText]): The second ciphertext.

    Returns:
        CipherText: The result of the operation.
    """
    ...

def serialize_bit(
    cs: CPUCryptoSystem,
    ciphertext: CipherText,
) -> str:
    """Serialize the given ciphertext using binary encoding scheme.

    Args:
        cs (CPUCryptoSystem): The cryptosystem to use.
        ciphertext (Ciphertext): The ciphertext to serialize.

    Returns:
        str: The serialized ciphertext.
    """
    ...

def deserialize_bit(
    cs: CPUCryptoSystem,
    serialized: str,
) -> CipherText:
    """Deserialize the given ciphertext using binary encoding scheme.

    Args:
        cs (CPUCryptoSystem): The cryptosystem to use.
        serialized (str): The serialized ciphertext.

    Returns:
        Ciphertext: The deserialized ciphertext.
    """
    ...

def serialize_bitwise(
    cs: CPUCryptoSystem,
    ciphertext: List[CipherText],
) -> str:
    """Serialize the given ciphertext using binary encoding scheme.

    Args:
        cs (CPUCryptoSystem): The cryptosystem to use.
        ciphertext (List[CipherText]): The ciphertext to serialize.

    Returns:
        str: The serialized ciphertexts.
    """
    ...

def deserialize_bitwise(
    cs: CPUCryptoSystem,
    serialized: str,
) -> List[CipherText]:
    """Deserialize the given ciphertext using binary encoding scheme.

    Args:
        cs (CPUCryptoSystem): The cryptosystem to use.
        serialized (str): The serialized ciphertext.

    Returns:
        List[CipherText]: The deserialized ciphertexts.
    """
    ...
