from pycofhe.cpu_cryptosystem import (
    CPUCryptoSystemCipherTextTensor,
    CPUCryptoSystemPlainTextTensor,
)

from .network_core import (
    ComputeOperation,
    ComputeOperationInstance,
    ComputeOperationOperand,
    ComputeOperationType,
    ComputeRequest,
    ComputeResponseStatus,
    CPUCryptoSystemClientNode,
    DataEncryptionType,
    DataType,
)


def perform_tensor_op(
    client_node: CPUCryptoSystemClientNode,
    op: ComputeOperation,
    t1: CPUCryptoSystemCipherTextTensor | CPUCryptoSystemPlainTextTensor,
    t2: CPUCryptoSystemCipherTextTensor | CPUCryptoSystemPlainTextTensor,
) -> CPUCryptoSystemCipherTextTensor | CPUCryptoSystemPlainTextTensor:
    """Perform a tensor operation on two tensors.

    Args:
        client_node (CPUCryptoSystemClientNode): The client node.
        op (ComputeOperation): The operation to perform.
        t1 (CPUCryptoSystemCipherTextTensor|CPUCryptoSystemPlainTextTensor): The first tensor.
        t2 (CPUCryptoSystemCipherTextTensor|CPUCryptoSystemPlainTextTensor): The second tensor.

    Returns:
        CPUCryptoSystemCipherTextTensor|CPUCryptoSystemPlainTextTensor: The result tensor.
    """
    t1_encryption_type = (
        DataEncryptionType.CIPHERTEXT
        if isinstance(t1, CPUCryptoSystemCipherTextTensor)
        else DataEncryptionType.PLAINTEXT
    )
    t2_encryption_type = (
        DataEncryptionType.CIPHERTEXT
        if isinstance(t2, CPUCryptoSystemCipherTextTensor)
        else DataEncryptionType.PLAINTEXT
    )

    if (
        t1_encryption_type == DataEncryptionType.PLAINTEXT
        and t2_encryption_type == DataEncryptionType.PLAINTEXT
    ):
        if op == ComputeOperation.ADD:
            return client_node.cryptosystem.add_plaintext_tensors(t1, t2)
        if op == ComputeOperation.SUBTRACT:
            return client_node.cryptosystem.add_plaintext_tensors(
                t1, client_node.cryptosystem.negate_plaintext_tensor(t2)
            )
        if op == ComputeOperation.MULTIPLY:
            return client_node.cryptosystem.multiply_plaintext_tensors(t1, t2)
        if op == ComputeOperation.DIVIDE:
            raise NotImplementedError("Division not supported for now")
        raise ValueError(f"Unsupported operation: {op}")

    t1_data = (
        client_node.cryptosystem.serialize_ciphertext_tensor(t1)
        if t1_encryption_type == DataEncryptionType.CIPHERTEXT
        else client_node.cryptosystem.serialize_plaintext_tensor(t1)
    )
    t2_data = (
        client_node.cryptosystem.serialize_ciphertext_tensor(t2)
        if t2_encryption_type == DataEncryptionType.CIPHERTEXT
        else client_node.cryptosystem.serialize_plaintext_tensor(t2)
    )
    request = ComputeRequest(
        ComputeOperationInstance(
            ComputeOperationType.BINARY,
            op,
            [
                ComputeOperationOperand(
                    DataType.TENSOR, t1_encryption_type, t1_data
                ),
                ComputeOperationOperand(
                    DataType.TENSOR, t2_encryption_type, t2_data
                ),
            ],
        )
    )

    response = client_node.compute(request)

    if response.status != ComputeResponseStatus.OK:
        raise ValueError(f"Failed to perform operation: {response.data}")

    return client_node.cryptosystem.deserialize_ciphertext_tensor(
        response.data_bytes
    )


def perform_tensor_decryption(
    client_node: CPUCryptoSystemClientNode,
    t: CPUCryptoSystemCipherTextTensor,
) -> CPUCryptoSystemPlainTextTensor:
    """Decrypt a ciphertext tensor.

    Args:
        client_node (CPUCryptoSystemClientNode): The client node.
        t (CPUCryptoSystemCipherTextTensor): The ciphertext tensor.

    Returns:
        CPUCryptoSystemPlainTextTensor: The plaintext tensor.
    """
    request = ComputeRequest(
        ComputeOperationInstance(
            ComputeOperationType.UNARY,
            ComputeOperation.DECRYPT,
            [
                ComputeOperationOperand(
                    DataType.TENSOR,
                    DataEncryptionType.CIPHERTEXT,
                    client_node.cryptosystem.serialize_ciphertext_tensor(t),
                )
            ],
        )
    )

    response = client_node.compute(request)

    if response.status != ComputeResponseStatus.OK:
        raise ValueError(f"Failed to decrypt tensor: {response.data}")

    return client_node.cryptosystem.deserialize_plaintext_tensor(
        response.data_bytes
    )
