"""Test the binary CPU cryptosystem related utils functions."""

from __future__ import annotations
import random

from dotenv import dotenv_values

from pycofhe.network import (
    encrypt_bit,
    decrypt_bit,
    homomorphic_nand,
    encrypt_bitwise,
    decrypt_bitwise,
    homomorphic_and,
    homomorphic_or,
    homomorphic_xor,
    homomorphic_not,
    homomorphic_add,
    homomorphic_sub,
    homomorphic_lt,
    homomorphic_eq,
    homomorphic_gt,
    serialize_bit,
    deserialize_bit,
    serialize_bitwise,
    deserialize_bitwise,
)
from pycofhe.network.network_core import make_cpu_cryptosystem_client_node


def test_encrypt_bitwise_and_decrypt_bitwise(client_node):
    """Test the encrypt_bitwise function."""
    num = random.randint(0, 100)
    encrypted_num = encrypt_bitwise(
        client_node.cryptosystem, client_node.network_encryption_key, num
    )
    decrypted_num = decrypt_bitwise(client_node, encrypted_num)
    assert decrypted_num == num


def test_encrypt_bit_and_decrypt_bit(client_node):
    """Test the encrypt_bit function."""
    bit = random.randint(0, 1)
    encrypted_bit = encrypt_bit(
        client_node.cryptosystem, client_node.network_encryption_key, bit
    )
    decrypted_bit = decrypt_bit(client_node, encrypted_bit)
    assert decrypted_bit == bit


def test_homomorphic_nand(client_node):
    """Test the homomorphic_nand function."""
    bit1 = random.randint(0, 1)
    bit2 = random.randint(0, 1)
    encrypted_bit1 = encrypt_bit(
        client_node.cryptosystem, client_node.network_encryption_key, bit1
    )
    encrypted_bit2 = encrypt_bit(
        client_node.cryptosystem, client_node.network_encryption_key, bit2
    )
    encrypted_nand = homomorphic_nand(
        client_node, encrypted_bit1, encrypted_bit2
    )
    decrypted_nand = decrypt_bit(client_node, encrypted_nand)
    assert decrypted_nand == (~(bit1 & bit2) + 2)


def test_homomorphic_and(client_node):
    """Test the homomorphic_and function."""
    num1 = random.randint(0, 100)
    num2 = random.randint(0, 100)
    encrypted_num1 = encrypt_bitwise(
        client_node.cryptosystem, client_node.network_encryption_key, num1
    )
    encrypted_num2 = encrypt_bitwise(
        client_node.cryptosystem, client_node.network_encryption_key, num2
    )
    encrypted_and = homomorphic_and(client_node, encrypted_num1, encrypted_num2)
    decrypted_and = decrypt_bitwise(client_node, encrypted_and)
    assert decrypted_and == num1 & num2


def test_homomorphic_or(client_node):
    """Test the homomorphic_or function."""
    num1 = random.randint(0, 100)
    num2 = random.randint(0, 100)
    encrypted_num1 = encrypt_bitwise(
        client_node.cryptosystem, client_node.network_encryption_key, num1
    )
    encrypted_num2 = encrypt_bitwise(
        client_node.cryptosystem, client_node.network_encryption_key, num2
    )
    encrypted_or = homomorphic_or(client_node, encrypted_num1, encrypted_num2)
    decrypted_or = decrypt_bitwise(client_node, encrypted_or)
    assert decrypted_or == num1 | num2


def test_homomorphic_xor(client_node):
    """Test the homomorphic_xor function."""
    num1 = random.randint(0, 100)
    num2 = random.randint(0, 100)
    encrypted_num1 = encrypt_bitwise(
        client_node.cryptosystem, client_node.network_encryption_key, num1
    )
    encrypted_num2 = encrypt_bitwise(
        client_node.cryptosystem, client_node.network_encryption_key, num2
    )
    encrypted_xor = homomorphic_xor(client_node, encrypted_num1, encrypted_num2)
    decrypted_xor = decrypt_bitwise(client_node, encrypted_xor)
    assert decrypted_xor == num1 ^ num2


def test_homomorphic_not(client_node):
    """Test the homomorphic_not function."""
    num = random.randint(0, 100)
    encrypted_num = encrypt_bitwise(
        client_node.cryptosystem, client_node.network_encryption_key, num
    )
    encrypted_not = homomorphic_not(client_node, encrypted_num)
    decrypted_not = decrypt_bitwise(client_node, encrypted_not)
    assert decrypted_not == ((~num) + 2**32)


def test_homomorphic_add(client_node):
    """Test the homomorphic_add function."""

    num1 = random.randint(0, 100)
    num2 = random.randint(0, 100)
    encrypted_num1 = encrypt_bitwise(
        client_node.cryptosystem, client_node.network_encryption_key, num1
    )
    encrypted_num2 = encrypt_bitwise(
        client_node.cryptosystem, client_node.network_encryption_key, num2
    )
    encrypted_sum = homomorphic_add(client_node, encrypted_num1, encrypted_num2)
    decrypted_sum = decrypt_bitwise(client_node, encrypted_sum)
    assert decrypted_sum == num1 + num2


def test_homomorphic_sub(client_node):
    """Test the homomorphic_sub function."""
    num1 = random.randint(0, 100)
    num2 = random.randint(0, 100)
    # only unsigned number(32 bit) is supported for now
    num1 += num2
    encrypted_num1 = encrypt_bitwise(
        client_node.cryptosystem, client_node.network_encryption_key, num1
    )
    encrypted_num2 = encrypt_bitwise(
        client_node.cryptosystem, client_node.network_encryption_key, num2
    )
    encrypted_diff = homomorphic_sub(
        client_node, encrypted_num1, encrypted_num2
    )
    decrypted_diff = decrypt_bitwise(client_node, encrypted_diff)
    assert decrypted_diff == num1 - num2


def test_homomorphic_lt(client_node):
    """Test the homomorphic_lt function."""
    num1 = random.randint(0, 100)
    num2 = random.randint(0, 100)
    encrypted_num1 = encrypt_bitwise(
        client_node.cryptosystem, client_node.network_encryption_key, num1
    )
    encrypted_num2 = encrypt_bitwise(
        client_node.cryptosystem, client_node.network_encryption_key, num2
    )
    encrypted_lt = homomorphic_lt(client_node, encrypted_num1, encrypted_num2)
    decrypted_lt = decrypt_bit(client_node, encrypted_lt) == 1
    assert decrypted_lt == (num1 < num2)


def test_homomorphic_eq(client_node):
    """Test the homomorphic_eq function."""
    num1 = random.randint(0, 100)
    num2 = random.randint(0, 100)
    encrypted_num1 = encrypt_bitwise(
        client_node.cryptosystem, client_node.network_encryption_key, num1
    )
    encrypted_num2 = encrypt_bitwise(
        client_node.cryptosystem, client_node.network_encryption_key, num2
    )
    encrypted_eq = homomorphic_eq(client_node, encrypted_num1, encrypted_num2)
    decrypted_eq = decrypt_bit(client_node, encrypted_eq) == 1
    assert decrypted_eq == (num1 == num2)


def test_homomorphic_gt(client_node):
    """Test the homomorphic_gt function."""
    num1 = random.randint(0, 100)
    num2 = random.randint(0, 100)
    encrypted_num1 = encrypt_bitwise(
        client_node.cryptosystem, client_node.network_encryption_key, num1
    )
    encrypted_num2 = encrypt_bitwise(
        client_node.cryptosystem, client_node.network_encryption_key, num2
    )
    encrypted_gt = homomorphic_gt(client_node, encrypted_num1, encrypted_num2)
    decrypted_gt = decrypt_bit(client_node, encrypted_gt) == 1
    assert decrypted_gt == (num1 > num2)


def test_serialization_deserialization_bit(client_node):
    """Test the serialization and deserialization of bits."""
    bit = random.randint(0, 1)
    encrypted_bit = encrypt_bit(
        client_node.cryptosystem, client_node.network_encryption_key, bit
    )
    serialized_bit = serialize_bit(client_node.cryptosystem, encrypted_bit)
    deserialized_bit = deserialize_bit(client_node.cryptosystem, serialized_bit)
    decrypted_bit = decrypt_bit(client_node, deserialized_bit)
    assert decrypted_bit == bit


def test_serialization_deserialization_bitwise(client_node):
    """Test the serialization and deserialization of bitwise numbers."""
    num = random.randint(0, 100)
    encrypted_num = encrypt_bitwise(
        client_node.cryptosystem, client_node.network_encryption_key, num
    )
    serialized_num = serialize_bitwise(client_node.cryptosystem, encrypted_num)
    deserialized_num = deserialize_bitwise(
        client_node.cryptosystem, serialized_num
    )
    decrypted_num = decrypt_bitwise(client_node, deserialized_num)
    assert decrypted_num == num