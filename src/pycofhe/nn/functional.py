"""Functional module for neural network operations."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pycofhe.network.network_core import DataEncryptionType
from pycofhe.nn.tensor_type import TensorType

if TYPE_CHECKING:
    from pycofhe.cryptosystems.cryptosystem import (
        CipherText,
        PartialDecryptionResult,
        PlainText,
        PublicKey,
        SecretKey,
        SecretKeyShare,
    )
    from pycofhe.network.network_core import ClientNode
    from pycofhe.network.reencryptor import PKCEncryptor
    from pycofhe.tensor.tensor_core import GenericTensor


from pycofhe.network import (
    ComputeOperation,
    perform_tensor_decryption,
    perform_tensor_op,
)
from pycofhe.tensor import Tensor
from pycofhe.utils import scale_down, scale_up


def linear(
    client_node: ClientNode[
        SecretKey,
        SecretKeyShare,
        PublicKey,
        PlainText,
        CipherText,
        PartialDecryptionResult,
        PKCEncryptor,
    ],
    input_tensor: GenericTensor[CipherText] | GenericTensor[PlainText] | Tensor,
    weights_tensor: (
        GenericTensor[CipherText] | GenericTensor[PlainText] | Tensor
    ),
    bias_tensor: (
        GenericTensor[CipherText] | GenericTensor[PlainText] | Tensor | None
    ) = None,
    scaling_factor: int = 1,
    input_tensor_type: TensorType = TensorType.CipherText,
    weights_tensor_type: TensorType = TensorType.Float,
    bias_tensor_type: TensorType = TensorType.Float,
) -> GenericTensor[CipherText] | GenericTensor[PlainText]:
    """Perform a linear operation on the input tensor using the weights tensor and bias tensor.

        Output = input * weights + bias

        Also any tensor of instance Tensor will be scaled by scaling_factor appropriately
        
        Args:
            client_node (ClientNode): The client node.
            input_tensor (GenericTensor[CipherText]|GenericTensor[PlainText]): The input tensor.
            weights_tensor (GenericTensor[CipherText]|GenericTensor[PlainText]): The weights tensor.
            bias_tensor (GenericTensor[CipherText]|GenericTensor[PlainText]|None, optional): The bias tensor. Defaults to None.
            scaling_factor (int, optional): The scaling factor. Defaults to 1.
            input_tensor_type (TensorType, optional): The type of the input tensor. Defaults to TensorType.CipherText.
            weights_tensor_type (TensorType, optional): The type of the weights tensor. Defaults to TensorType.Float.
            bias_tensor_type (TensorType, optional): The type of the bias tensor. Defaults to TensorType.Float.
            
        Returns:
            GenericTensor[CipherText]|GenericTensor[PlainText]: The result tensor.
    """

    if input_tensor.shape[1] != weights_tensor.shape[0]:
        raise ValueError(
            f"Input tensor shape {input_tensor.shape} and weights tensor shape {weights_tensor.shape} are not compatible"
        )
    if (
        bias_tensor is not None
        and bias_tensor.shape[1] != weights_tensor.shape[1]
    ):
        raise ValueError(
            f"Bias tensor shape {bias_tensor.shape} and weights tensor shape {weights_tensor.shape} are not compatible"
        )

    if (
        bias_tensor is not None
        and bias_tensor.shape[0] != input_tensor.shape[0]
    ):
        bias_tensor = bias_tensor.broadcast(
            [input_tensor.shape[0], bias_tensor.shape[1]]
        )

    if scaling_factor != 1:
        if input_tensor_type == TensorType.Float:
            input_tensor = scale_up(
                client_node.cryptosystem, input_tensor, scaling_factor
            )
        if weights_tensor_type == TensorType.Float:
            weights_tensor = scale_up(
                client_node.cryptosystem, weights_tensor, scaling_factor
            )
        if bias_tensor is not None and bias_tensor_type == TensorType.Float:
            bias_tensor = scale_up(
                client_node.cryptosystem, bias_tensor, scaling_factor**2
            )

    result = perform_tensor_op(
        client_node,
        ComputeOperation.MULTIPLY,
        input_tensor,
        weights_tensor,
        (
            DataEncryptionType.CIPHERTEXT
            if input_tensor_type == TensorType.CipherText
            else DataEncryptionType.PLAINTEXT
        ),
        (
            DataEncryptionType.CIPHERTEXT
            if weights_tensor_type == TensorType.CipherText
            else DataEncryptionType.PLAINTEXT
        ),
    )
    result = (
        perform_tensor_op(
            client_node,
            ComputeOperation.ADD,
            result,
            bias_tensor,
            (
                DataEncryptionType.CIPHERTEXT
                if input_tensor_type == TensorType.CipherText
                or weights_tensor_type == TensorType.CipherText
                else DataEncryptionType.PLAINTEXT
            ),
            (
                DataEncryptionType.CIPHERTEXT
                if bias_tensor_type == TensorType.CipherText
                else DataEncryptionType.PLAINTEXT
            ),
        )
        if bias_tensor is not None
        else result
    )

    return result


def linear_decryption(
    client_node: ClientNode[
        SecretKey,
        SecretKeyShare,
        PublicKey,
        PlainText,
        CipherText,
        PartialDecryptionResult,
        PKCEncryptor,
    ],
    input_tensor: GenericTensor[CipherText],
    scaling_factor: int = 1,
) -> Tensor:
    """Perform decryption of the linear output tensor.

    Args:
        client_node (ClientNode): The client node.
        input_tensor (GenericTensor[CipherText]): The input tensor.
        scaling_factor (int, optional): The scaling factor. Defaults to 1.

    Returns:
        Tensor: The decrypted tensor.
    """
    result = perform_tensor_decryption(client_node, input_tensor)
    return scale_down(client_node.cryptosystem, result, scaling_factor)
