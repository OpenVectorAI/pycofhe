"""Provides util functions for scaling tensors."""

from __future__ import annotations

from typing import TYPE_CHECKING

import math


if TYPE_CHECKING:
    from pycofhe.tensor.tensor_core import GenericTensor
    from pycofhe.cryptosystems.cryptosystem import (
        CipherText,
        CryptoSystem,
        PartialDecryptionResult,
        PlainText,
        PublicKey,
        SecretKey,
        SecretKeyShare,
    )

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
    cryptosystem: CryptoSystem[
        SecretKey,
        SecretKeyShare,
        PublicKey,
        PlainText,
        CipherText,
        PartialDecryptionResult,
    ],
    input_tensor: Tensor,
    scaling_factor: int,
    min_value: int = 16,
) -> GenericTensor[PlainText]:
    """Scale up a tensor by a factor.

    Args:
        cryptosystem (CryptoSystem): The cryptosystem.
        input_tensor (Tensor): The input tensor.
        scaling_factor (int): The scaling factor.
        min_value (int, optional): The minimum value. Defaults to 16.
            If a absolute value is less than min_value, it is set to min_value.

    Returns:
        CryptoSystemPlainTextTensor: The scaled up tensor.
    """

    flattened_tensor = input_tensor.flatten()
    scaled_tensor_values: list[float] = [
        math.floor(flattened_tensor[i] * scaling_factor)
        for i in range(flattened_tensor.size)
    ]
    scaled_tensor_values = [
        sign(value) * max(min_value, abs(value))
        for value in scaled_tensor_values
    ]
    return cryptosystem.make_plaintext_tensor(
        input_tensor.shape, scaled_tensor_values
    )


def scale_down(
    cryptosystem: CryptoSystem[
        SecretKey,
        SecretKeyShare,
        PublicKey,
        PlainText,
        CipherText,
        PartialDecryptionResult,
    ],
    input_tensor: GenericTensor[PlainText],
    scaling_factor: int,
    depth: int = 1,
) -> Tensor:
    """Scale down a tensor by a factor.

    Args:
        cryptosystem (CryptoSystem): The cryptosystem.
        input_tensor (Tensor[PlainText]): The input tensor.
        scaling_factor (int): The scaling factor.
        depth (int, optional): The depth of the computation. Defaults to 1.
            Values are  scaled down by scaling_factor ** depth

    Returns:
        Tensor: The scaled down tensor.
    """
    flattened_tensor = cryptosystem.get_float_from_plaintext_tensor(
        input_tensor, scaling_factor, depth
    )
    return Tensor(input_tensor.shape, flattened_tensor)  # type: ignore
