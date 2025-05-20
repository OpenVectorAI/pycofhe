from __future__ import annotations

from typing import TYPE_CHECKING


if TYPE_CHECKING:
    from pycofhe.cryptosystems.cryptosystem import (
        SecretKey,
        SecretKeyShare,
        PublicKey,
        PlainText,
        CipherText,
        PartialDecryptionResult,
    )

    from pycofhe.network.network_core import ClientNode
    from pycofhe.network.reencryptor import PKCEncryptor
    from pycofhe.tensor.tensor_core import GenericTensor


from pycofhe.network.network_core import (
    ComputeOperation,
    ComputeOperationInstance,
    ComputeOperationOperand,
    ComputeOperationType,
    ComputeRequest,
    ComputeResponseStatus,
    DataEncryptionType,
    DataType,
)


def perform_op(
    client_node: ClientNode[
        SecretKey,
        SecretKeyShare,
        PublicKey,
        PlainText,
        CipherText,
        PartialDecryptionResult,
        PKCEncryptor,
    ],
    op: ComputeOperation,
    ct1: CipherText | PlainText,
    ct2: CipherText | PlainText,
    ct1_encryption_type: DataEncryptionType = DataEncryptionType.CIPHERTEXT,
    ct2_encryption_type: DataEncryptionType = DataEncryptionType.CIPHERTEXT,
) -> CipherText | PlainText:
    """Perform an operation on two ciphertexts or plaintexts.

    Args:
        client_node (ClientNode): The client node.
        op (ComputeOperation): The operation to perform.
        ct1 (CipherText|PlainText): The first operand.
        ct2 (CipherText|PlainText): The second operand.
        ct1_encryption_type (DataEncryptionType): The encryption type of the first operand.
        ct2_encryption_type (DataEncryptionType): The encryption type of the second operand.

    Returns:
        CipherText|PlainText: The result of the operation.
    """
    if (
        ct1_encryption_type == DataEncryptionType.PLAINTEXT
        and ct2_encryption_type == DataEncryptionType.PLAINTEXT
    ):
        if op == ComputeOperation.ADD:
            return client_node.cryptosystem.add_plaintexts(ct1, ct2)
        if op == ComputeOperation.SUBTRACT:
            return client_node.cryptosystem.add_plaintexts(
                ct1, client_node.cryptosystem.negate_plaintext(ct2)
            )
        if op == ComputeOperation.MULTIPLY:
            return client_node.cryptosystem.multiply_plaintexts(ct1, ct2)
        if op == ComputeOperation.DIVIDE:
            raise NotImplementedError("Division not supported for now")

    ct1_data = (
        client_node.cryptosystem.serialize_ciphertext(ct1)
        if ct1_encryption_type == DataEncryptionType.CIPHERTEXT
        else client_node.cryptosystem.serialize_plaintext(ct1)
    )
    ct2_data = (
        client_node.cryptosystem.serialize_ciphertext(ct2)
        if ct2_encryption_type == DataEncryptionType.CIPHERTEXT
        else client_node.cryptosystem.serialize_plaintext(ct2)
    )
    request = ComputeRequest(
        ComputeOperationInstance(
            ComputeOperationType.BINARY,
            op,
            [
                ComputeOperationOperand(
                    DataType.SINGLE, ct1_encryption_type, ct1_data
                ),
                ComputeOperationOperand(
                    DataType.SINGLE, ct2_encryption_type, ct2_data
                ),
            ],
        )
    )

    response = client_node.compute(request)

    if response.status != ComputeResponseStatus.OK:
        raise ValueError(f"Failed to perform operation: {response.data.hex()}")

    return client_node.cryptosystem.deserialize_ciphertext(response.data)


def perform_decryption(
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
) -> PlainText:
    """Decrypt a ciphertext.

    Args:
        client_node (ClientNode): The client node.
        ct (CipherText): The ciphertext.

    Returns:
        PlainText: The plaintext.
    """
    request = ComputeRequest(
        ComputeOperationInstance(
            ComputeOperationType.UNARY,
            ComputeOperation.DECRYPT,
            [
                ComputeOperationOperand(
                    DataType.SINGLE,
                    DataEncryptionType.CIPHERTEXT,
                    client_node.cryptosystem.serialize_ciphertext(ct),
                )
            ],
        )
    )

    response = client_node.compute(request)

    if response.status != ComputeResponseStatus.OK:
        raise ValueError(f"Failed to decrypt ciphertext: {response.data.hex()}")

    return client_node.cryptosystem.deserialize_plaintext(response.data)


def perform_reencryption(
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
    serialized_pub_key: bytes,
) -> bytes:
    """Perform a reencryption on a ciphertext.

    Args:
        client_node (ClientNode): The client node.
        ct (CipherText): The ciphertext.
        key_pair (RSAPKCEncryptorReencryptionKeyPair[PKCEncryptor]): The reencryption key pair.

    Returns:
        bytes: The reencrypted ciphertext.
    """

    request = ComputeRequest(
        ComputeOperationInstance(
            ComputeOperationType.BINARY,
            ComputeOperation.REENCRYPT,
            [
                ComputeOperationOperand(
                    DataType.SINGLE,
                    DataEncryptionType.CIPHERTEXT,
                    client_node.cryptosystem.serialize_ciphertext(ct),
                ),
                ComputeOperationOperand(
                    DataType.SINGLE,
                    DataEncryptionType.PLAINTEXT,
                    serialized_pub_key,
                ),
            ],
        )
    )

    response = client_node.compute(request)

    if response.status != ComputeResponseStatus.OK:
        raise ValueError(f"Failed to perform operation: {response.data.hex()}")

    return response.data


def perform_tensor_op(
    client_node: ClientNode[
        SecretKey,
        SecretKeyShare,
        PublicKey,
        PlainText,
        CipherText,
        PartialDecryptionResult,
        PKCEncryptor,
    ],
    op: ComputeOperation,
    t1: GenericTensor[CipherText] | GenericTensor[PlainText],
    t2: GenericTensor[CipherText] | GenericTensor[PlainText],
    t1_encryption_type: DataEncryptionType = DataEncryptionType.CIPHERTEXT,
    t2_encryption_type: DataEncryptionType = DataEncryptionType.CIPHERTEXT,
) -> GenericTensor[CipherText] | GenericTensor[PlainText]:
    """Perform a tensor operation on two tensors.

    Args:
        client_node (ClientNode): The client node.
        op (ComputeOperation): The operation to perform.
        t1 (GenericTensor[CipherText]|GenericTensor[PlainText]): The first tensor.
        t2 (GenericTensor[CipherText]|GenericTensor[PlainText]): The second tensor.
        t1_encryption_type (DataEncryptionType): The encryption type of the first tensor.
        t2_encryption_type (DataEncryptionType): The encryption type of the second tensor.

    Returns:
        GenericTensor[CipherText]|GenericTensor[PlainText]: The result tensor.
    """

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
        raise ValueError(f"Failed to perform operation: {response.data.hex()}")

    return client_node.cryptosystem.deserialize_ciphertext_tensor(
        response.data
    )


def perform_tensor_decryption(
    client_node: ClientNode[
        SecretKey,
        SecretKeyShare,
        PublicKey,
        PlainText,
        CipherText,
        PartialDecryptionResult,
        PKCEncryptor,
    ],
    t: GenericTensor[CipherText],
) -> GenericTensor[PlainText]:
    """Decrypt a ciphertext tensor.

    Args:
        client_node (ClientNode): The client node.
        t (GenericTensor[CipherText]): The ciphertext tensor.

    Returns:
        GenericTensor[PlainText]: The plaintext tensor.
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
        raise ValueError(f"Failed to decrypt tensor: {response.data.hex()}")

    return client_node.cryptosystem.deserialize_plaintext_tensor(
        response.data
    )


def peform_tensor_reencryption(
    client_node: ClientNode[
        SecretKey,
        SecretKeyShare,
        PublicKey,
        PlainText,
        CipherText,
        PartialDecryptionResult,
        PKCEncryptor,
    ],
    ct: GenericTensor[CipherText],
    serialized_pub_key: bytes,
) -> bytes:
    """Perform a reencryption on a ciphertext tensor.

    Args:
        client_node (ClientNode): The client node.
        ct (GenericTensor[CipherText]): The ciphertext tensor.
        key_pair (RSAPKCEncryptorReencryptionKeyPair[PKCEncryptor]): The reencryption key pair.

    Returns:
        bytes: The reencrypted ciphertext tensor.
    """

    request = ComputeRequest(
        ComputeOperationInstance(
            ComputeOperationType.BINARY,
            ComputeOperation.REENCRYPT,
            [
                ComputeOperationOperand(
                    DataType.TENSOR,
                    DataEncryptionType.CIPHERTEXT,
                    client_node.cryptosystem.serialize_ciphertext_tensor(ct),
                ),
                ComputeOperationOperand(
                    DataType.SINGLE,
                    DataEncryptionType.PLAINTEXT,
                    serialized_pub_key,
                ),
            ],
        )
    )

    response = client_node.compute(request)

    if response.status != ComputeResponseStatus.OK:
        raise ValueError(f"Failed to perform operation: {response.data.hex()}")

    return response.data
