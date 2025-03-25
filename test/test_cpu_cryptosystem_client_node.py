"""Test the CPU cryptosystem client client_node class."""

from __future__ import annotations

import pytest


from pycofhe.network import (
    ComputeOperation,
    ComputeOperationInstance,
    ComputeOperationOperand,
    ComputeOperationType,
    ComputeRequest,
    ComputeResponse,
    ComputeResponseStatus,
    DataEncryptionType,
    DataType,
    perform_tensor_op,
    perform_tensor_decryption,
)

def test_compute_response():
    """Test ComputeResponse class"""
    r = ComputeResponse(ComputeResponseStatus.OK, "SomeData")
    assert r.status == ComputeResponseStatus.OK
    assert r.data == "SomeData"

    r.status = ComputeResponseStatus.ERROR
    r.data = "ErrorData"
    assert r.status == ComputeResponseStatus.ERROR
    assert r.data == "ErrorData"

    r.data_bytes = b"\x01\x02"
    assert r.data_bytes == b"\x01\x02"


def test_compute_operation_operand_str_data():
    """Test ComputeOperationOperand class"""
    operand = ComputeOperationOperand(
        DataType.SINGLE, DataEncryptionType.PLAINTEXT, "123"
    )
    assert operand.data_type == DataType.SINGLE
    assert operand.encryption_type == DataEncryptionType.PLAINTEXT
    assert operand.data == "123"

    operand.data = "456"
    assert operand.data == "456"


def test_compute_operation_operand_bytes_data():
    """Test ComputeOperationOperand class"""
    operand = ComputeOperationOperand(
        DataType.SINGLE, DataEncryptionType.CIPHERTEXT, b"789"
    )
    assert operand.data_type == DataType.SINGLE
    assert operand.encryption_type == DataEncryptionType.CIPHERTEXT
    assert operand.data_bytes == b"789"


def test_compute_operation_instance():
    """Test ComputeOperationInstance class"""
    op1 = ComputeOperationOperand(
        DataType.SINGLE, DataEncryptionType.PLAINTEXT, "123"
    )
    op2 = ComputeOperationOperand(
        DataType.SINGLE, DataEncryptionType.PLAINTEXT, "456"
    )
    instance = ComputeOperationInstance(
        ComputeOperationType.BINARY,
        ComputeOperation.ADD,
        [op1, op2],
    )
    assert instance.operation_type == ComputeOperationType.BINARY
    assert instance.operation == ComputeOperation.ADD
    assert len(instance.operands) == 2
    assert instance.operands[0].data == "123"
    assert instance.operands[1].data == "456"


def test_compute_request():
    """Test ComputeRequest class"""
    op = ComputeOperationOperand(
        DataType.SINGLE, DataEncryptionType.PLAINTEXT, "999"
    )
    instance = ComputeOperationInstance(
        ComputeOperationType.UNARY,
        ComputeOperation.DECRYPT,
        [op],
    )
    req = ComputeRequest(instance)
    assert req.operation.operation_type == ComputeOperationType.UNARY
    assert req.operation.operation == ComputeOperation.DECRYPT
    assert req.operation.operands[0].data == "999"


def test_client_node_multiply(client_node):
    """
    Test a homomorphic multiply and decrypt sequence using a CPUCryptoSystemClientNode.
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

    dop = ComputeOperationOperand(
        DataType.TENSOR, DataEncryptionType.CIPHERTEXT, res.data_bytes
    )
    dop_instance = ComputeOperationInstance(
        ComputeOperationType.UNARY, ComputeOperation.DECRYPT, [dop]
    )
    req = ComputeRequest(dop_instance)
    res = client_node.compute(req)

    dres = cs.deserialize_plaintext_tensor(res.data_bytes)
    float_res = cs.get_float_from_plaintext_tensor(dres)

    # Explanation:
    #   c1 * p1 => [1*5, 32*6, 3*7, 4*8] = [5, 192, 21, 32]
    #   c2 = p1 => [5, 6, 7, 8]
    #   multiply => [5*5, 192*6, 21*7, 32*8] = [25, 1152, 147, 256]
    assert float_res == [25.0, 1152.0, 147.0, 256.0]


def test_util_funcs(client_node):
    """
    Test a homomorphic multiply and decrypt sequence using a CPUCryptoSystemClientNode.
    """
    cs = client_node.cryptosystem
    pk = client_node.network_encryption_key

    c1 = cs.encrypt_tensor(pk, cs.make_plaintext_tensor([4], [1, 2**5, 3, 4]))
    p1 = cs.make_plaintext_tensor([4], [5, 6, 7, 8])

    res = perform_tensor_op(client_node, ComputeOperation.MULTIPLY, c1, p1)
    dres = perform_tensor_decryption(client_node, res)

    float_res = cs.get_float_from_plaintext_tensor(dres)

    assert float_res == [5.0, 192.0, 21.0, 32.0]