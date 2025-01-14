"""Test the cpu_cryptosystem module."""

import pytest

from pycofhe.cpu_cryptosystem import (
    CipherText,
    CPUCryptoSystem,
    PlainText,
    PublicKey,
    SecretKey,
)


@pytest.fixture
def ccs():
    """
    Create a CPUCryptoSystem fixture initialized with security_level=128, k=32, compact=False.
    This will be reused in all tests.
    """
    return CPUCryptoSystem(128, 32, False)


def test_keygen_secret_key(ccs):
    """
    Test generating a fresh SecretKey from CPUCryptoSystem.
    """
    sk = ccs.keygen()
    assert isinstance(
        sk, SecretKey
    ), "keygen() did not return a SecretKey instance."


def test_keygen_public_key(ccs):
    """
    Test generating a PublicKey from an existing SecretKey.
    """
    sk = ccs.keygen()
    pk = ccs.keygen(sk)
    assert isinstance(
        pk, PublicKey
    ), "keygen(SecretKey) did not return a PublicKey instance."


def test_encrypt_decrypt_int_round_trip(ccs):
    """
    Test a basic encryption/decryption round trip using an integer plaintext.
    """
    sk = ccs.keygen()
    pk = ccs.keygen(sk)

    original_value = 42
    pt = ccs.make_plaintext(original_value)

    ct = ccs.encrypt(pk, pt)
    assert isinstance(ct, CipherText), "encrypt() did not return a CipherText."

    decrypted_pt = ccs.decrypt(sk, ct)
    assert isinstance(
        decrypted_pt, PlainText
    ), "decrypt() did not return a PlainText."

    decrypted_value = ccs.get_float_from_plaintext(decrypted_pt)

    assert (
        abs(decrypted_value - original_value) < 1e-6
    ), f"Decrypted value mismatch: {decrypted_value} != {original_value}"


def test_add_ciphertexts_int(ccs):
    """
    Test homomorphic addition of two ciphertexts containing integer plaintexts.
    """
    sk = ccs.keygen()
    pk = ccs.keygen(sk)

    pt_val1 = ccs.make_plaintext(10)
    pt_val2 = ccs.make_plaintext(5)

    ct1 = ccs.encrypt(pk, pt_val1)
    ct2 = ccs.encrypt(pk, pt_val2)

    ct_sum = ccs.add_ciphertexts(pk, ct1, ct2)
    assert isinstance(
        ct_sum, CipherText
    ), "add_ciphertexts() did not return a CipherText."

    pt_sum = ccs.decrypt(sk, ct_sum)
    decrypted_sum = ccs.get_float_from_plaintext(pt_sum)
    assert (
        abs(decrypted_sum - (10 + 5)) < 1e-6
    ), f"Homomorphic addition result mismatch: got {decrypted_sum}"


def test_scal_ciphertext_int(ccs):
    """
    Test scaling (multiplying) a ciphertext by an integer plaintext scalar.
    """
    sk = ccs.keygen()
    pk = ccs.keygen(sk)

    pt_val = ccs.make_plaintext(6)
    ct = ccs.encrypt(pk, pt_val)

    scalar = ccs.make_plaintext(7)
    ct_scaled = ccs.scal_ciphertext(pk, scalar, ct)
    assert isinstance(
        ct_scaled, CipherText
    ), "scal_ciphertext() did not return a CipherText."

    pt_scaled = ccs.decrypt(sk, ct_scaled)
    decrypted_scaled = ccs.get_float_from_plaintext(pt_scaled)
    assert (
        abs(decrypted_scaled - (6 * 7)) < 1e-6
    ), f"Homomorphic scaling result mismatch: got {decrypted_scaled}"


def test_negate_ciphertext_int(ccs):
    """
    Test negating (multiplying by -1) a ciphertext that contains an integer plaintext.
    """
    sk = ccs.keygen()
    pk = ccs.keygen(sk)

    pt_val = ccs.make_plaintext(8)
    ct = ccs.encrypt(pk, pt_val)

    ct_neg = ccs.negate_ciphertext(pk, ct)
    pt_neg = ccs.decrypt(sk, ct_neg)
    decrypted_neg = ccs.get_float_from_plaintext(pt_neg)

    assert (
        abs(decrypted_neg - (-8)) < 1e-6
    ), f"Negate ciphertext result mismatch: got {decrypted_neg}"


def test_add_plaintexts_int(ccs):
    """
    Test adding two integer plaintexts.
    """
    pt1 = ccs.make_plaintext(3)
    pt2 = ccs.make_plaintext(4)

    pt_sum = ccs.add_plaintexts(pt1, pt2)
    val_sum = ccs.get_float_from_plaintext(pt_sum)
    assert (
        abs(val_sum - 7) < 1e-6
    ), f"add_plaintexts() result mismatch: got {val_sum}"


def test_multiply_plaintexts_int(ccs):
    """
    Test multiplying two integer plaintexts.
    """
    pt1 = ccs.make_plaintext(5)
    pt2 = ccs.make_plaintext(9)

    pt_prod = ccs.multiply_plaintexts(pt1, pt2)
    val_prod = ccs.get_float_from_plaintext(pt_prod)
    assert (
        abs(val_prod - (5 * 9)) < 1e-6
    ), f"multiply_plaintexts() result mismatch: got {val_prod}"


def test_serialize_deserialize_system(ccs):
    """
    Test serializing and deserializing the CPUCryptoSystem.
    """
    serialized = ccs.serialize()
    ccs_deserialized = CPUCryptoSystem.deserialize(serialized)
    assert isinstance(
        ccs_deserialized, CPUCryptoSystem
    ), "Failed to deserialize CPUCryptoSystem."


def test_serialize_deserialize_keys_int(ccs):
    """
    Test serializing and deserializing SecretKey and PublicKey using integer-based cryptosystem usage.
    """
    sk = ccs.keygen()
    pk = ccs.keygen(sk)

    sk_data = ccs.serialize_secret_key(sk)
    sk_new = ccs.deserialize_secret_key(sk_data)
    assert isinstance(sk_new, SecretKey), "Failed to deserialize SecretKey."

    pk_data = ccs.serialize_public_key(pk)
    pk_new = ccs.deserialize_public_key(pk_data)
    assert isinstance(pk_new, PublicKey), "Failed to deserialize PublicKey."


def test_serialize_deserialize_plaintext_int(ccs):
    """
    Test serializing and deserializing a PlainText that contains an integer value.
    """
    pt_val = ccs.make_plaintext(123)
    pt_data = ccs.serialize_plaintext(pt_val)
    pt_new = ccs.deserialize_plaintext(pt_data)

    recovered_val = ccs.get_float_from_plaintext(pt_new)
    assert (
        abs(recovered_val - 123) < 1e-6
    ), f"Deserialized PlainText value mismatch: got {recovered_val}"


def test_serialize_deserialize_ciphertext_int(ccs):
    """
    Test serializing and deserializing a CipherText that encrypts an integer value.
    """
    sk = ccs.keygen()
    pk = ccs.keygen(sk)

    pt_val = ccs.make_plaintext(999)
    ct = ccs.encrypt(pk, pt_val)

    ct_data = ccs.serialize_ciphertext(ct)
    ct_new = ccs.deserialize_ciphertext(ct_data)

    # Decrypt newly deserialized ciphertext
    pt_recovered = ccs.decrypt(sk, ct_new)
    recovered_val = ccs.get_float_from_plaintext(pt_recovered)
    assert (
        abs(recovered_val - 999) < 1e-6
    ), f"Deserialized CipherText value mismatch: got {recovered_val}"


def test_encrypt_decrypt_tensor_int(ccs):
    """
    Test encryption/decryption of a tensor of integer plaintexts.
    """
    sk = ccs.keygen()
    pk = ccs.keygen(sk)

    values = [10, 20, 30]
    pt_tensor = ccs.make_plaintext_tensor([len(values)], values)

    ct_tensor = ccs.encrypt_tensor(pk, pt_tensor)

    decrypted_pt_tensor = ccs.decrypt_tensor(sk, ct_tensor)

    decrypted_values = ccs.get_float_from_plaintext_tensor(decrypted_pt_tensor)
    assert len(decrypted_values) == len(
        values
    ), "Decrypted tensor length mismatch."

    for orig, dec in zip(values, decrypted_values):
        assert (
            abs(dec - orig) < 1e-6
        ), f"Tensor decryption mismatch: {dec} != {orig}"


def test_serialize_deserialize_plaintext_tensor_int(ccs):
    """
    Test serializing and deserializing a tensor of integer PlainTexts.
    """
    values = [7, 14, 21]
    pt_tensor = ccs.make_plaintext_tensor([len(values)], values)

    data_bytes = ccs.serialize_plaintext_tensor(pt_tensor)
    pt_tensor_new = ccs.deserialize_plaintext_tensor(data_bytes)

    original_vals = ccs.get_float_from_plaintext_tensor(pt_tensor)
    new_vals = ccs.get_float_from_plaintext_tensor(pt_tensor_new)
    assert (
        original_vals == new_vals
    ), f"Deserialized PlainText tensor mismatch: {new_vals} != {original_vals}"


def test_serialize_deserialize_ciphertext_tensor_int(ccs):
    """
    Test serializing and deserializing a tensor of CipherTexts that encrypt integer values.
    """
    sk = ccs.keygen()
    pk = ccs.keygen(sk)

    values = [100, 200, 300]
    pt_tensor = ccs.make_plaintext_tensor([len(values)], values)
    ct_tensor = ccs.encrypt_tensor(pk, pt_tensor)

    data_bytes = ccs.serialize_ciphertext_tensor(ct_tensor)
    ct_tensor_new = ccs.deserialize_ciphertext_tensor(data_bytes)

    pt_tensor_new = ccs.decrypt_tensor(sk, ct_tensor_new)
    new_vals = ccs.get_float_from_plaintext_tensor(pt_tensor_new)
    assert len(values) == len(new_vals), "CipherText tensor length mismatch."

    for orig, dec in zip(values, new_vals):
        assert (
            abs(dec - orig) < 1e-6
        ), f"Deserialized CipherText tensor mismatch: got {dec} != {orig}"
