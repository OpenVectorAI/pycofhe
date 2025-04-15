from __future__ import annotations

from pycofhe.network import (
    ComputeOperation,
    perform_tensor_op,
    perform_tensor_decryption,
)
from pycofhe.network.network_core import DataEncryptionType


def test_util_funcs(client_node):
    """
    Test a homomorphic multiply and decrypt sequence using a ClientNode.
    """
    cs = client_node.cryptosystem
    pk = client_node.network_encryption_key

    c1 = cs.encrypt_tensor(pk, cs.make_plaintext_tensor([4], [1, 2**5, 3, 4]))
    p1 = cs.make_plaintext_tensor([4], [5, 6, 7, 8])

    res = perform_tensor_op(
        client_node,
        ComputeOperation.MULTIPLY,
        c1,
        p1,
        DataEncryptionType.CIPHERTEXT,
        DataEncryptionType.PLAINTEXT,
    )
    dres = perform_tensor_decryption(client_node, res)

    float_res = cs.get_float_from_plaintext_tensor(dres)

    assert float_res == [5.0, 192.0, 21.0, 32.0]
