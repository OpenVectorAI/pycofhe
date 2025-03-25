"""Base class for all neural network modules."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, TypeVar

if TYPE_CHECKING:
    from pycofhe.tensor.tensor_core import GenericTensor

from pycofhe.network import CPUCryptoSystemClientNode

input_tensor_value_type = TypeVar("input_tensor_value_type")
output_tensor_value_type = TypeVar("output_tensor_value_type")


class Module(ABC):
    """Base class for all neural network modules."""

    __slots__ = ("_client_node",)

    client_node: CPUCryptoSystemClientNode

    def __init__(self, client_node: CPUCryptoSystemClientNode) -> None:
        """Initialize the module.

        Args:
            client_node (CPUCryptoSystemClientNode): The execution environment.
        """
        self._client_node = client_node

    @abstractmethod
    def forward(
        self,
        input_tensor: GenericTensor[input_tensor_value_type],
        *args,
        **kwargs,
    ) -> GenericTensor[output_tensor_value_type]:
        """Forward pass.

        Args:
            client_node (CPUCryptoSystemClientNode|CPUCryptoSystem): The execution environment.
            *inputs (GenericTensor): The input tensors.

        Returns:
            GenericTensor: The output tensor.
        """
        raise NotImplementedError
    
    def __call__(
        self,
        input_tensor: GenericTensor[input_tensor_value_type],
        *args,
        **kwargs,
    ) -> GenericTensor[output_tensor_value_type]:
        """Call the forward method."""
        return self.forward(input_tensor, *args, **kwargs)
