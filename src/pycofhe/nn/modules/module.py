"""Base class for all neural network modules."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any, Generic, TypeVar


if TYPE_CHECKING:
    from pycofhe.tensor.tensor_core import GenericTensor
    from pycofhe.network.network_core import ClientNode

SecretKey = TypeVar("SecretKey")
SecretKeyShare = TypeVar("SecretKeyShare")
PublicKey = TypeVar("PublicKey")
PlainText = TypeVar("PlainText")
CipherText = TypeVar("CipherText")
PartialDecryptionResult = TypeVar("PartialDecryptionResult")
PKCEncryptor = TypeVar("PKCEncryptor")

class Module(
    Generic[
        SecretKey,
        SecretKeyShare,
        PublicKey,
        PlainText,
        CipherText,
        PartialDecryptionResult,
        PKCEncryptor,
    ],
    ABC,
):
    """A Generic Base class for all neural network modules."""

    __slots__ = ("_client_node",)

    client_node: ClientNode[
        SecretKey,
        SecretKeyShare,
        PublicKey,
        PlainText,
        CipherText,
        PartialDecryptionResult,
        PKCEncryptor,
    ]

    def __init__(
        self,
        client_node: ClientNode[
            SecretKey,
            SecretKeyShare,
            PublicKey,
            PlainText,
            CipherText,
            PartialDecryptionResult,
            PKCEncryptor,
        ],
    ) -> None:
        """Initialize the module.

        Args:
            client_node (ClientNode): The execution environment.
        """
        self._client_node = client_node

    @abstractmethod
    def forward(
        self,
        input_tensor: GenericTensor[Any],
        *args,
        **kwargs,
    ) -> GenericTensor[Any]:
        """Forward pass.

        Args:
            client_node (ClientNode|CPUCryptoSystem): The execution environment.
            *inputs (GenericTensor): The input tensors.

        Returns:
            GenericTensor: The output tensor.
        """
        raise NotImplementedError

    def __call__(
        self,
        input_tensor: GenericTensor[Any],
        *args,
        **kwargs,
    ) -> GenericTensor[Any]:
        """Call the forward method."""
        return self.forward(input_tensor, *args, **kwargs)
