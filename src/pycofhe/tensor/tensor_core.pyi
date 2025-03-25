"""Typing stubs for the tensor module"""

from __future__ import annotations

from typing import Generic, List, TypeVar, Union, overload

# pylint: disable=unused-argument,unnecessary-ellipsis

T = TypeVar("T")

class GenericTensor(Generic[T]):
    """
    A generic tensor class.
    """

    @overload
    def __init__(self, value: T) -> None:
        """
        Construct a 0-dimensional tensor with the given value.

        Args:
            value (T): The value of the tensor.
        """
        ...

    @overload
    def __init__(self, shape: List[int], value: T) -> None:
        """
        Construct a tensor with the given shape and value.

        Args:
            shape (List[int]): The shape of the tensor.
            value (T): The value of the tensor.
        """
        ...

    @overload
    def __init__(self, n: int, value: T) -> None:
        """
        Construct a 1-dimensional tensor with the given size and value.

        Args:
            n (int): The size of the tensor.
            value (T): The value of the tensor.
        """
        ...

    @overload
    def __init__(self, n: int, m: int, value: T) -> None:
        """
        Construct a 2-dimensional tensor with the given size and value.

        Args:
            n (int): The number of rows of the tensor.
            m (int): The number of columns of the tensor.
            value (T): The value of the tensor.
        """
        ...

    @overload
    def __init__(self, shape: List[int], values: List[T]) -> None:
        """
        Construct a tensor with the given shape and list of values.

        Args:
            shape (List[int]): The shape of the tensor.
            values (List[T]): The values of the tensor.
        """
        ...

    @overload
    def __init__(self, *args, **kwargs) -> None:
        """
        Initialize a GenericTensor with various constructors.
        """
        ...

    @property
    def shape(self) -> List[int]:
        """
        The shape of the tensor.

        Returns:
            List[int]: The shape of the tensor.
        """
        ...

    @property
    def size(self) -> int:
        """
        The number of elements in the tensor.

        Returns:
            int: The number of elements in the tensor.
        """
        ...

    @property
    def ndim(self) -> int:
        """
        The number of dimensions of the tensor.

        Returns:
            int: The number of dimensions of the tensor.
        """
        ...

    @property
    def is_scalar(self) -> bool:
        """
        Whether the tensor is a scalar.

        Returns:
            bool: Whether the tensor is a scalar.
        """
        ...

    @property
    def is_vector(self) -> bool:
        """
        Whether the tensor is a vector.

        Returns:
            bool: Whether the tensor is a vector.
        """
        ...

    @property
    def is_matrix(self) -> bool:
        """
        Whether the tensor is a matrix.

        Returns:
            bool: Whether the tensor is a matrix.
        """
        ...

    @property
    def is_contiguous(self) -> bool:
        """
        Whether the tensor is contiguous.

        Returns:
            bool: Whether the tensor is contiguous.
        """
        ...

    @overload
    def __getitem__(self, index: int) -> T:
        """
        Get the element at the given index.

        Args:
            index (int): The index of the element.

        Returns:
            T: The element at the given index.
        """
        ...

    @overload
    def __getitem__(self, indices: List[int]) -> T:
        """
        Get the element at the given indices.

        Args:
            indices (List[int]): The indices of the element.

        Returns:
            T: The element at the given indices.

        Example:
            >>> t = Tensor([2, 2], [1, 2, 3, 4])
            >>> t[[0, 1]]
            2
        """
        ...

    @overload
    def __getitem__(self, key: Union[int, List[int]]) -> T:
        """
        Get the element at the given index or indices.

        Args:
            key (Union[int, List[int]]): The index or list of indices of the element.

        Returns:
            T: The element at the given index or indices.

        Example:
            >>> t = Tensor([2, 2], [1, 2, 3, 4])
            >>> t[1]
            2
            >>> t[[0, 1]]
            2
        """
        ...

    @overload
    def __setitem__(self, index: int, value: T) -> None:
        """
        Set the element at the given index.

        Args:
            index (int): The index of the element.
            value (T): The value to set.
        """
        ...

    @overload
    def __setitem__(self, indices: List[int], value: T) -> None:
        """
        Set the element at the given indices.

        Args:
            indices (List[int]): The indices of the element.
            value (T): The value to set.

        Example:
            >>> t = Tensor([2, 2], [1, 2, 3, 4])
            >>> t[[0, 1]] = 5
            >>> t
            Tensor([2, 2], [1, 5, 3, 4])
        """
        ...

    @overload
    def __setitem__(self, key: Union[int, List[int]], value: T) -> None:
        """
        Set the element at the given index or indices.

        Args:
            key (Union[int, List[int]]): The index or list of indices of the element.
            value (T): The value to set.

        Example:
            >>> t = Tensor([2, 2], [1, 2, 3, 4])
            >>> t[1] = 5
            >>> t[[0, 1]] = 6
            >>> t
            Tensor([2, 2], [1, 6, 3, 4])
        """
        ...

    def __str__(self) -> str:
        """
        Return the string representation of the tensor.

        Returns:
            str: The string representation of the tensor.
        """
        ...

    def flatten(self) -> GenericTensor[T]:
        """
        Flatten the tensor.

        Returns:
            GenericTensor[T]: The flattened tensor.
        """
        ...

    def reshape(self, shape: List[int]) -> GenericTensor[T]:
        """
        Reshape the tensor.

        Args:
            shape (List[int]): The new shape of the tensor.

        Returns:
            GenericTensor[T]: The reshaped tensor.
        """
        ...

    def make_contiguous(self) -> None:
        """
        Make the tensor contiguous.
        """
        ...

    def transpose(self) -> GenericTensor[T]:
        """
        Transpose the tensor.

        Returns:
            GenericTensor[T]: The transposed tensor.
        """
        ...

    def broadcast(self, shape: List[int]) -> GenericTensor[T]:
        """
        Broadcast the tensor to the given shape.

        Args:
            shape (List[int]): The shape to broadcast to.

        Returns:
            GenericTensor[T]: The broadcasted tensor.
        """
        ...

Tensor = GenericTensor[float]
IntTensor = GenericTensor[int]