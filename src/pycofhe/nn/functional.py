"""Functional module for neural network operations."""

from __future__ import annotations

from pycofhe.cpu_cryptosystem import (
    CPUCryptoSystemCipherTextTensor,
    CPUCryptoSystemPlainTextTensor,
)
from pycofhe.network import (
    ComputeOperation,
    CPUCryptoSystemClientNode,
    perform_tensor_decryption,
    perform_tensor_op,
)
from pycofhe.tensor import Tensor
from pycofhe.utils import scale_down, scale_up


def linear(
    client_node: CPUCryptoSystemClientNode,
    input_tensor: (
        CPUCryptoSystemCipherTextTensor
        | CPUCryptoSystemPlainTextTensor
        | Tensor
    ),
    weights_tensor: (
        CPUCryptoSystemCipherTextTensor
        | CPUCryptoSystemPlainTextTensor
        | Tensor
    ),
    bias_tensor: (
        CPUCryptoSystemCipherTextTensor
        | CPUCryptoSystemPlainTextTensor
        | Tensor
        | None
    ) = None,
    scaling_factor: int = 1,
) -> CPUCryptoSystemCipherTextTensor | CPUCryptoSystemPlainTextTensor:
    """Perform a linear operation on the input tensor using the weights tensor and bias tensor.

        Output = input * weights + bias

        Also any tensor of instance Tensor will be scaled by scaling_factor appropriately
    Args:
        client_node (CPUCryptoSystemClientNode): The client node.
        input_tensor (CPUCryptoSystemCipherTextTensor|CPUCryptoSystemPlainTextTensor): The input tensor.
        weights_tensor (CPUCryptoSystemCipherTextTensor|CPUCryptoSystemPlainTextTensor): The weights tensor.
        bias_tensor (CPUCryptoSystemCipherTextTensor|CPUCryptoSystemPlainTextTensor|None, optional): The bias tensor. Defaults to None.

    Returns:
        CPUCryptoSystemCipherTextTensor|CPUCryptoSystemPlainTextTensor: The result tensor.
    """

    if input_tensor.shape[1] != weights_tensor.shape[0]:
        raise ValueError(
            f"Input tensor shape {input_tensor.shape} and weights tensor shape {weights_tensor.shape} are not compatible"
        )
    if bias_tensor is not None and bias_tensor.shape[1] != weights_tensor.shape[1]:
        raise ValueError(
            f"Bias tensor shape {bias_tensor.shape} and weights tensor shape {weights_tensor.shape} are not compatible"
        )
    
    if bias_tensor is not None and bias_tensor.shape[0] != input_tensor.shape[0]:
        bias_tensor = bias_tensor.broadcast([input_tensor.shape[0], bias_tensor.shape[1]])

    if scaling_factor != 1:
        if isinstance(input_tensor, Tensor):
            input_tensor = scale_up(client_node, input_tensor, scaling_factor)
        if isinstance(weights_tensor, Tensor):
            weights_tensor = scale_up(
                client_node, weights_tensor, scaling_factor
            )
        if isinstance(bias_tensor, Tensor):
            bias_tensor = scale_up(client_node, bias_tensor, scaling_factor**2)

    result = perform_tensor_op(
        client_node, ComputeOperation.MULTIPLY, input_tensor, weights_tensor
    )
    result = (
        perform_tensor_op(
            client_node, ComputeOperation.ADD, result, bias_tensor
        )
        if bias_tensor is not None
        else result
    )

    return result


def linear_decryption(
    client_node: CPUCryptoSystemClientNode,
    input_tensor: CPUCryptoSystemCipherTextTensor,
    scaling_factor: int = 1,
) -> Tensor:
    """Perform decryption of the linear output tensor.

    Args:
        client_node (CPUCryptoSystemClientNode): The client node.
        input_tensor (CPUCryptoSystemCipherTextTensor): The input tensor.
        scaling_factor (int, optional): The scaling factor. Defaults to 1.

    Returns:
        Tensor: The decrypted tensor.
    """
    result = perform_tensor_decryption(client_node, input_tensor)
    if scaling_factor != 1:
        result = scale_down(client_node, result, scaling_factor)

    return result
