"""Test the neural network module."""

from __future__ import annotations

import pytest

import random

from pycofhe.tensor import Tensor
from pycofhe.nn import Module, Linear

def test_module():
    """Test the Module class."""
    with pytest.raises(TypeError):
        Module()


def get_random_tensor(size: tuple[int, int], is_int: bool = False, max: int = 256, min: int =16) -> Tensor:
    """Get a random tensor."""
    tensor_values: list[float]|list[int] = []
    for _ in range(size[0]*size[1]):
        if is_int:
            tensor_values.append(random.randint(min, max))
        else:
            tensor_values.append(random.uniform(min, max))
    return Tensor(size, tensor_values)

def linear_in_plaintext(input_tensor: Tensor, weights: Tensor, bias: Tensor | None = None) -> Tensor:
    """Perform a linear operation in plaintext.

    Args:
        input_tensor (Tensor): The input tensor with shape (n, I).
        weights (Tensor): The weights tensor with shape (I, O).
        bias (Tensor | None): The bias tensor with shape (1, O) or (O,). Defaults to None.

    Returns:
        Tensor: The resulting tensor with shape (n, O).
    """
    n, I = input_tensor.shape
    I_weights, O = weights.shape

    # Validate dimensions
    assert I == I_weights, "Input tensor's second dimension must match weights' first dimension."

    # Initialize output tensor values
    output_tensor_values = []

    # Perform the linear operation
    for i in range(n):
        output_row = []
        for o in range(O):
            output_value = 0
            for j in range(I):
                output_value += input_tensor[[i,j]] * weights[[j,o]]
            if bias is not None:
                # Broadcast the bias if needed
                output_value += bias[[0,o]]
            output_row.append(output_value)
        output_tensor_values.append(output_row)

    flattended_output_tensor_values = [value for row in output_tensor_values for value in row]
    return Tensor((n, O), flattended_output_tensor_values)

def compare_tensors(tensor1: Tensor, tensor2: Tensor, tolerance: float = 0.1) -> bool:
    """Compare two tensors.

    Args:
        tensor1 (Tensor): The first tensor.
        tensor2 (Tensor): The second tensor.
        tolerance (float, optional): The tolerance. Defaults to 0.1. It is a percentage.

    Returns:
        bool: Whether the tensors are equal.
    """
    if tensor1.shape != tensor2.shape:
        return False
    tensor1 = tensor1.flatten()
    tensor2 = tensor2.flatten()
    for i in range(tensor1.size):
        if abs(tensor1[i] - tensor2[i])/100 > tolerance:
            assert False, f"tensor1: {tensor1[i]}, tensor2: {tensor2[i]}"
            return False
    return True

def run_linear(client_node, input_size, output_size, scaling_factor, tolerance, is_int):
    """Test the Linear class."""
    input_size = 10
    output_size = 5
    weights = get_random_tensor((input_size, output_size))
    bias = get_random_tensor((1, output_size))
    scaling_factor = 10000

    linear = Linear(client_node, input_size, output_size, weights, bias, scaling_factor)

    input_tensor = get_random_tensor((3, input_size))
    output_tensor = linear( input_tensor)
    output_decrypted = linear.map_back(output_tensor)
    output_tensor_expected = linear_in_plaintext(input_tensor, weights, bias)

    assert compare_tensors(output_decrypted, output_tensor_expected,20)

def test_linear(client_node):
    """Test the Linear class."""
    input_size = 10
    output_size = 5
    scaling_factor = 10000

    # Test with integer values
    tolerance = 2
    is_int = True
    run_linear(client_node, input_size, output_size, scaling_factor, tolerance, is_int)

    # Test with float values
    tolerance=20
    is_int = False
    run_linear(client_node, input_size, output_size, scaling_factor, tolerance, is_int)
