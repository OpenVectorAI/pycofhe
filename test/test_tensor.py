"""Test the tensor module."""

import pytest

from pycofhe.tensor import Tensor


def test_tensor_initialization_scalar():
    """
    Test initializing a 0-dimensional tensor (scalar) and verify its properties.
    """
    value = 3.14
    tensor = Tensor(value)

    assert tensor.shape == []
    assert tensor.size == 1
    assert tensor.ndim == 0
    assert tensor.is_scalar is True
    assert tensor.is_vector is False
    assert tensor.is_matrix is False
    assert tensor.is_contiguous is True

    assert tensor[0] == value


def test_tensor_initialization_with_shape_and_value():
    """
    Test initializing a tensor with a given shape and initial value.
    """
    shape = [2, 3]
    initial_value = 1.0
    tensor = Tensor(shape, initial_value)

    assert tensor.shape == shape
    assert tensor.size == 6
    assert tensor.ndim == 2
    assert tensor.is_scalar is False
    assert tensor.is_vector is False
    assert tensor.is_matrix is True

    for i in range(shape[0]):
        for j in range(shape[1]):
            assert tensor[i, j] == initial_value


def test_tensor_initialization_with_shape_and_values():
    """
    Test initializing a tensor with a given shape and a list of values.
    """
    shape = [2, 2]
    values = [1.0, 2.0, 3.0, 4.0]
    tensor = Tensor(shape, values)

    assert tensor.shape == shape
    assert tensor.size == 4
    assert tensor.ndim == 2
    assert tensor.is_scalar is False
    assert tensor.is_vector is False
    assert tensor.is_matrix is True
    assert tensor.is_contiguous is True

    assert tensor[0, 0] == 1.0
    assert tensor[0, 1] == 2.0
    assert tensor[1, 0] == 3.0
    assert tensor[1, 1] == 4.0


def test_tensor_initialization_1d():
    """
    Test initializing a 1-dimensional tensor.
    """
    n = 5
    initial_value = 2.5
    tensor = Tensor(n, initial_value)

    assert tensor.shape == [n]
    assert tensor.size == n
    assert tensor.ndim == 1
    assert tensor.is_scalar is False
    assert tensor.is_vector is True
    assert tensor.is_matrix is False
    assert tensor.is_contiguous is True

    for i in range(n):
        assert tensor[i] == initial_value


def test_tensor_initialization_2d():
    """
    Test initializing a 2-dimensional tensor.
    """
    n, m = 3, 4
    initial_value = 0.0
    tensor = Tensor(n, m, initial_value)

    assert tensor.shape == [n, m]
    assert tensor.size == n * m
    assert tensor.ndim == 2
    assert tensor.is_scalar is False
    assert tensor.is_vector is False
    assert tensor.is_matrix is True
    assert tensor.is_contiguous is True

    for i in range(n):
        for j in range(m):
            assert tensor[i, j] == initial_value


def test_tensor_getitem_single_index():
    """
    Test accessing elements in a tensor using single indices.
    """
    shape = [3]
    values = [10.0, 20.0, 30.0]
    tensor = Tensor(shape, values)

    assert tensor[0] == 10.0
    assert tensor[1] == 20.0
    assert tensor[2] == 30.0


def test_tensor_getitem_multi_index():
    """
    Test accessing elements in a tensor using multiple indices.
    """
    shape = [2, 3]
    values = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0]
    tensor = Tensor(shape, values)

    assert tensor[0, 0] == 1.0
    assert tensor[0, 1] == 2.0
    assert tensor[0, 2] == 3.0
    assert tensor[1, 0] == 4.0
    assert tensor[1, 1] == 5.0
    assert tensor[1, 2] == 6.0


def test_tensor_setitem_single_index():
    """
    Test setting elements in a tensor using single indices.
    """
    shape = [3]
    values = [10.0, 20.0, 30.0]
    tensor = Tensor(shape, values)

    tensor[0] = 100.0
    tensor[2] = 300.0

    assert tensor[0] == 100.0
    assert tensor[1] == 20.0
    assert tensor[2] == 300.0


def test_tensor_setitem_multi_index():
    """
    Test setting elements in a tensor using multiple indices.
    """
    shape = [2, 2]
    values = [1.0, 2.0, 3.0, 4.0]
    tensor = Tensor(shape, values)

    tensor[0, 1] = 20.0
    tensor[1, 0] = 30.0

    assert tensor[0, 0] == 1.0
    assert tensor[0, 1] == 20.0
    assert tensor[1, 0] == 30.0
    assert tensor[1, 1] == 4.0


def test_tensor_reshape():
    """
    Test reshaping a tensor and verify the new shape and element arrangement.
    """
    original_shape = [2, 3]
    values = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0]
    tensor = Tensor(original_shape, values)

    new_shape = [3, 2]
    reshaped_tensor = tensor.reshape(new_shape)

    assert reshaped_tensor.shape == new_shape
    assert reshaped_tensor.size == 6
    assert reshaped_tensor.ndim == 2
    assert reshaped_tensor.is_matrix is True

    # Assuming row-major order
    assert reshaped_tensor[0, 0] == 1.0
    assert reshaped_tensor[0, 1] == 2.0
    assert reshaped_tensor[1, 0] == 3.0
    assert reshaped_tensor[1, 1] == 4.0
    assert reshaped_tensor[2, 0] == 5.0
    assert reshaped_tensor[2, 1] == 6.0

    # Original tensor remains unchanged
    assert tensor.shape == original_shape
    for i in range(2):
        for j in range(3):
            assert tensor[i, j] == values[i * 3 + j]


def test_tensor_flatten():
    """
    Test flattening a tensor and verify the new shape and element arrangement.
    """
    shape = [2, 2]
    values = [1.0, 2.0, 3.0, 4.0]
    tensor = Tensor(shape, values)

    flattened_tensor = tensor.flatten()

    assert flattened_tensor.shape == [4]
    assert flattened_tensor.size == 4
    assert flattened_tensor.ndim == 1
    assert flattened_tensor.is_vector is True

    assert flattened_tensor[0] == 1.0
    assert flattened_tensor[1] == 2.0
    assert flattened_tensor[2] == 3.0
    assert flattened_tensor[3] == 4.0
