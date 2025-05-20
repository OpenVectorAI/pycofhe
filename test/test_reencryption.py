"""Test the Reencryptor class and related functionality."""

from __future__ import annotations

from pycofhe.network import (
    ComputeOperation,
    ComputeOperationInstance,
    ComputeOperationOperand,
    ComputeOperationType,
    ComputeRequest,
    ComputeResponse,
    ComputeResponseStatus,
    DataEncryptionType,
    DataType
)

def test_tesnor_reencryption(client_node):
    """
    Test a homomorphic multiply and reencrypt sequence using a ClientNode.
    """
    cs = client_node.cryptosystem
    pk = client_node.network_encryption_key

    c1 = cs.encrypt_tensor(pk, cs.make_plaintext_tensor([4], [1, 2**5, 3, 4]))
    p1 = cs.make_plaintext_tensor([4], [5, 6, 7, 8])
    c = cs.scal_ciphertext_tensors(pk, p1, c1)
    c2 = cs.encrypt_tensor(pk, p1)

    op1 = ComputeOperationOperand(
        DataType.TENSOR,
        DataEncryptionType.CIPHERTEXT,
        cs.serialize_ciphertext_tensor(c),
    )
    op2 = ComputeOperationOperand(
        DataType.TENSOR,
        DataEncryptionType.CIPHERTEXT,
        cs.serialize_ciphertext_tensor(c2),
    )

    op_instance = ComputeOperationInstance(
        ComputeOperationType.BINARY, ComputeOperation.MULTIPLY, [op1, op2]
    )
    req = ComputeRequest(op_instance)
    res = client_node.compute(req)
    res_ct = cs.deserialize_ciphertext_tensor(res.data)

    dop = ComputeOperationOperand(
        DataType.TENSOR, DataEncryptionType.CIPHERTEXT, res.data
    )
    reencryptor = client_node.reencryptor
    ser_key_pair = reencryptor.generate_serialized_key_pair()
    pub_key_op = ComputeOperationOperand(
        DataType.SINGLE,DataEncryptionType.PLAINTEXT, ser_key_pair[1])
    dop_instance = ComputeOperationInstance(
        ComputeOperationType.BINARY, ComputeOperation.REENCRYPT, [dop,pub_key_op]
    )
    req = ComputeRequest(dop_instance)
    res = client_node.compute(req)

    dres = reencryptor.decrypt_tensor(res.data,res_ct,ser_key_pair[0])
    float_res = cs.get_float_from_plaintext_tensor(dres)

    # Explanation:
    #   c1 * p1 => [1*5, 32*6, 3*7, 4*8] = [5, 192, 21, 32]
    #   c2 = p1 => [5, 6, 7, 8]
    #   multiply => [5*5, 192*6, 21*7, 32*8] = [25, 1152, 147, 256]
    assert float_res == [25.0, 1152.0, 147.0, 256.0]

def test_single_ciphertext_reencryption(client_node):
    """
    Test a homomorphic add and reencrypt sequence using a ClientNode.
    """
    cs = client_node.cryptosystem
    pk = client_node.network_encryption_key

    c1 = cs.encrypt(pk, cs.make_plaintext(4))
    p1 = cs.make_plaintext(5)
    c = cs.scal_ciphertext(pk, p1, c1)
    c2 = cs.encrypt(pk, p1)

    op1 = ComputeOperationOperand(
        DataType.SINGLE,
        DataEncryptionType.CIPHERTEXT,
        cs.serialize_ciphertext(c),
    )
    op2 = ComputeOperationOperand(
        DataType.SINGLE,
        DataEncryptionType.CIPHERTEXT,
        cs.serialize_ciphertext(c2),
    )

    op_instance = ComputeOperationInstance(
        ComputeOperationType.BINARY, ComputeOperation.ADD, [op1, op2]
    )
    req = ComputeRequest(op_instance)
    res = client_node.compute(req)
    res_ct = cs.deserialize_ciphertext(res.data)

    dop = ComputeOperationOperand(
        DataType.SINGLE, DataEncryptionType.CIPHERTEXT, res.data
    )
    reencryptor = client_node.reencryptor
    ser_key_pair = reencryptor.generate_serialized_key_pair()
    pub_key_op = ComputeOperationOperand(
        DataType.SINGLE,DataEncryptionType.PLAINTEXT, ser_key_pair[1])
    dop_instance = ComputeOperationInstance(
        ComputeOperationType.BINARY, ComputeOperation.REENCRYPT, [dop,pub_key_op]
    )
    req = ComputeRequest(dop_instance)
    res = client_node.compute(req)

    dres = reencryptor.decrypt(res.data,res_ct,ser_key_pair[0])
    float_res = cs.get_float_from_plaintext(dres)

    # Explanation:
    #   c1 * p1 => 4 * 5 = 20
    #   c2 = p1 => 5
    #   add => 20 + 5 = 25
    assert float_res == 25.0