"""Provides util functions for scaling tensors."""

from __future__ import annotations

import math

from pycofhe.cpu_cryptosystem import (
    CPUCryptoSystem,
    CPUCryptoSystemPlainTextTensor,
)
from pycofhe.network import CPUCryptoSystemClientNode
from pycofhe.tensor import Tensor

def sign(value: float) -> int:
    """Get the sign of a value.

    Args:
        value (float): The value.

    Returns:
        int: The sign of the value.
    """
    return 1 if value >= 0 else -1

def scale_up(
    cryptosystem: CPUCryptoSystem | CPUCryptoSystemClientNode,
    input_tensor: Tensor,
    scaling_factor: int,
    min_value: int = 16,
) -> CPUCryptoSystemPlainTextTensor:
    """Scale up a tensor by a factor.

    Args:
        cryptosystem (CPUCryptoSystem|CPUCryptoSystemClientNode): The cryptosystem.
        input_tensor (Tensor): The input tensor.
        scaling_factor (int): The scaling factor.
        min_value (int, optional): The minimum value. Defaults to 16.
            If a absolute value is less than min_value, it is set to min_value.

    Returns:
        CPUCryptoSystemPlainTextTensor: The scaled up tensor.
    """

    if isinstance(cryptosystem, CPUCryptoSystemClientNode):
        cryptosystem = cryptosystem.cryptosystem

    flattened_tensor = input_tensor.flatten()
    scaled_tensor_values = [
        math.floor(flattened_tensor[i] * scaling_factor)
        for i in range(flattened_tensor.size)
    ]
    scaled_tensor_values = [
        sign(value)*max(min_value, abs(value)) for value in scaled_tensor_values
    ]
    return cryptosystem.make_plaintext_tensor(
        input_tensor.shape, scaled_tensor_values
    )


def scale_down(
    cryptosystem: CPUCryptoSystem | CPUCryptoSystemClientNode,
    input_tensor: CPUCryptoSystemPlainTextTensor,
    scaling_factor: int,
    depth: int = 1,
) -> Tensor:
    """Scale down a tensor by a factor.

    Args:
        cryptosystem (CPUCryptoSystem|CPUCryptoSystemClientNode): The cryptosystem.
        input_tensor (CPUCryptoSystemPlainTextTensor): The input tensor.
        scaling_factor (int): The scaling factor.
        depth (int, optional): The depth of the computation. Defaults to 1.
            Values are  scaled down by scaling_factor ** depth

    Returns:
        Tensor: The scaled down tensor.
    """
    if isinstance(cryptosystem, CPUCryptoSystemClientNode):
        cryptosystem = cryptosystem.cryptosystem

    flattened_tensor = cryptosystem.get_float_from_plaintext_tensor(input_tensor,scaling_factor,depth)
    return Tensor(input_tensor.shape, flattened_tensor)
