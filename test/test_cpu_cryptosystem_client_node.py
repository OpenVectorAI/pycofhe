"""Test the CPU cryptosystem client client_node class."""

from __future__ import annotations

from dotenv import dotenv_values

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
    make_cpu_cryptosystem_client_node,
    NodeType,
    NodeDetails,
    CryptoSystemType,
    CryptoSystemDetails,
    ReencryptorType,
    ReencryptorDetails,
    NetworkDetails
)

def test_compute_response():
    """Test ComputeResponse class"""
    r = ComputeResponse(ComputeResponseStatus.OK, b"SomeData")
    assert r.status == ComputeResponseStatus.OK
    assert r.data == b"SomeData"

    r.status = ComputeResponseStatus.ERROR
    assert r.status == ComputeResponseStatus.ERROR

    r.data = b"\x01\x02"
    assert r.data == b"\x01\x02"


def test_compute_operation_instance():
    """Test ComputeOperationInstance class"""
    op1 = ComputeOperationOperand(
        DataType.SINGLE, DataEncryptionType.PLAINTEXT, b"123"
    )
    op2 = ComputeOperationOperand(
        DataType.SINGLE, DataEncryptionType.PLAINTEXT, b"456"
    )
    instance = ComputeOperationInstance(
        ComputeOperationType.BINARY,
        ComputeOperation.ADD,
        [op1, op2],
    )
    assert instance.operation_type == ComputeOperationType.BINARY
    assert instance.operation == ComputeOperation.ADD
    assert len(instance.operands) == 2
    assert instance.operands[0].data == b"123"
    assert instance.operands[1].data == b"456"


def test_compute_request():
    """Test ComputeRequest class"""
    op = ComputeOperationOperand(
        DataType.SINGLE, DataEncryptionType.PLAINTEXT, b"999"
    )
    instance = ComputeOperationInstance(
        ComputeOperationType.UNARY,
        ComputeOperation.DECRYPT,
        [op],
    )
    req = ComputeRequest(instance)
    assert req.operation.operation_type == ComputeOperationType.UNARY
    assert req.operation.operation == ComputeOperation.DECRYPT
    assert req.operation.operands[0].data == b"999"


def test_client_node_multiply(client_node):
    """
    Test a homomorphic multiply and decrypt sequence using a ClientNode.
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
        DataType.TENSOR, DataEncryptionType.CIPHERTEXT, res.data
    )
    dop_instance = ComputeOperationInstance(
        ComputeOperationType.UNARY, ComputeOperation.DECRYPT, [dop]
    )
    req = ComputeRequest(dop_instance)
    res = client_node.compute(req)

    dres = cs.deserialize_plaintext_tensor(res.data)
    float_res = cs.get_float_from_plaintext_tensor(dres)

    # Explanation:
    #   c1 * p1 => [1*5, 32*6, 3*7, 4*8] = [5, 192, 21, 32]
    #   c2 = p1 => [5, 6, 7, 8]
    #   multiply => [5*5, 192*6, 21*7, 32*8] = [25, 1152, 147, 256]
    assert float_res == [25.0, 1152.0, 147.0, 256.0]

def test_non_connected_client_node(client_node):
    real_nd = client_node.network_details
    self_node = NodeDetails(
        "127.0.0.1",
        "4478",
        NodeType.CLIENT_NODE,
    )
    cryptosystem_details = CryptoSystemDetails(
        CryptoSystemType.CoFHE_CPU,
        real_nd.cryptosystem_details.public_key,
        real_nd.cryptosystem_details.security_level,
        real_nd.cryptosystem_details.k,
        real_nd.cryptosystem_details.threshold,
        real_nd.cryptosystem_details.total_nodes,
        real_nd.cryptosystem_details.N
    )
    nodes:list[NodeDetails] = []
    reencryptor = ReencryptorDetails(
        ReencryptorType.RSA,
        2048)
    nd = NetworkDetails(
        self_node,
        nodes,
        cryptosystem_details,
        [],
        reencryptor,
    )
    env_vars = dotenv_values(".env")
    cert_path = env_vars.get("CERT_PATH")
    if cert_path is None:
        raise ValueError("CERT_PATH not found in environment variables.")
    client_node = make_cpu_cryptosystem_client_node(
        nd,
        cert_path,
    )

    cs = client_node.cryptosystem
    re = client_node.reencryptor