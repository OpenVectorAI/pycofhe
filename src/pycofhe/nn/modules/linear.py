from __future__ import annotations

from typing import TYPE_CHECKING, Generic

from pycofhe.nn.tensor_type import TensorType


if TYPE_CHECKING:
    from pycofhe.tensor.tensor_core import GenericTensor
    from pycofhe.network.network_core import ClientNode

from pycofhe.network import perform_tensor_decryption
from pycofhe.nn.functional import linear
from pycofhe.tensor import Tensor
from pycofhe.utils import scale_down, scale_up

from pycofhe.nn.modules.module import (
    Module,
    SecretKey,
    SecretKeyShare,
    PublicKey,
    PlainText,
    CipherText,
    PartialDecryptionResult,
    PKCEncryptor,
)


class Linear(
    Generic[
        SecretKey,
        SecretKeyShare,
        PublicKey,
        PlainText,
        CipherText,
        PartialDecryptionResult,
        PKCEncryptor,
    ],
    Module[
        SecretKey,
        SecretKeyShare,
        PublicKey,
        PlainText,
        CipherText,
        PartialDecryptionResult,
        PKCEncryptor,
    ],
):
    """Linear module for neural networks.This module performs a linear operation on the input tensor using the weights
    tensor and bias tensor.The output is calculated as follows:output = input * weights + bias"""

    __slots__ = (
        "_input_size",
        "_output_size",
        "_weights",
        "_bias",
        "_weights_tensor_type",
        "_bias_tensor_type",
        "_scaling_factor",
    )

    _input_size: int
    _output_size: int
    _weights: GenericTensor[CipherText] | GenericTensor[PlainText]
    _bias: GenericTensor[CipherText] | GenericTensor[PlainText] | None
    _weights_tensor_type: TensorType
    _bias_tensor_type: TensorType
    _scaling_factor: int

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
        input_size: int,
        output_size: int,
        weights: Tensor | GenericTensor[CipherText] | GenericTensor[PlainText],
        bias: (
            Tensor | GenericTensor[CipherText] | GenericTensor[PlainText] | None
        ) = None,
        weights_tensor_type: TensorType = TensorType.Float,
        bias_tensor_type: TensorType = TensorType.Float,
        encrypt_weights: bool = True,
        encrypt_bias: bool = True,
        scaling_factor: int = 1,
    ) -> None:
        """Initialize the Linear module.

        Args:
            client_node (ClientNode): The client node.
            input_size (int): The input size.
            output_size (int): The output size.
            weights (Tensor|GenericTensor[CipherText]|GenericTensor[PlainText]): The weights tensor.
            bias (Tensor|GenericTensor[CipherText]|GenericTensor[PlainText]|None, optional): The bias tensor. Defaults to None.
            encrypt_weights (bool, optional): Encrypt the weights tensor. Defaults to True.
            encrypt_bias (bool, optional): Encrypt the bias tensor. Defaults to True. If the weights tensor is encrypted, the bias tensor will be encrypted.
            scaling_factor (int, optional): The scaling factor. Defaults to 1.
            weights_tensor_type (TensorType, optional): The tensor type of the weights tensor. Defaults to TensorType.Float.
            bias_tensor_type (TensorType, optional): The tensor type of the bias tensor. Defaults to TensorType.Float.
        """
        super().__init__(client_node)

        self._input_size = input_size
        self._output_size = output_size
        self._scaling_factor = scaling_factor

        if weights_tensor_type == TensorType.Float:
            weights = scale_up(
                self._client_node.cryptosystem,
                weights,
                scaling_factor,
            )
            weights_tensor_type = TensorType.PlainText
        if bias_tensor_type == TensorType.Float and bias is not None:
            bias = scale_up(
                self._client_node.cryptosystem,
                bias,
                scaling_factor**2,
            )
            weights_tensor_type = TensorType.PlainText

        if encrypt_weights:
            weights = self._client_node.cryptosystem.encrypt_tensor(
                self._client_node.network_encryption_key, weights
            )
            weights_tensor_type = TensorType.CipherText

        if encrypt_bias and bias is not None:
            bias = self._client_node.cryptosystem.encrypt_tensor(
                self._client_node.network_encryption_key, bias
            )
            bias_tensor_type = TensorType.CipherText

        self._weights = weights
        self._bias = bias
        self._weights_tensor_type = weights_tensor_type
        self._bias_tensor_type = bias_tensor_type

    def forward(
        self,
        input_tensor: (
            GenericTensor[CipherText] | GenericTensor[PlainText] | Tensor
        ),
        input_tensor_type: TensorType = TensorType.CipherText,
        *args,
        **kwargs,
    ) -> GenericTensor[CipherText] | GenericTensor[PlainText]:
        """Perform the forward operation.

        Args:
            input_tensor (GenericTensor[CipherText]|GenericTensor[PlainText]|Tensor): The input tensor. Will be encrypted if it is a plaintext tensor.
                Pass `encrypt_input=False` to disable encryption using kwargs.
            input_tensor_type (TensorType, optional): The tensor type of the input tensor. Defaults to TensorType.CipherText.

        Returns:
            GenericTensor[CipherText]|GenericTensor[PlainText]: The output tensor.
        """
        if input_tensor_type == TensorType.Float:
            input_tensor = scale_up(
                self._client_node.cryptosystem,
                input_tensor,
                self._scaling_factor,
            )
            input_tensor_type = TensorType.PlainText

        encrypt_input = kwargs.get("encrypt_input", True)

        if encrypt_input and input_tensor_type != TensorType.CipherText:
            input_tensor = self._client_node.cryptosystem.encrypt_tensor(
                self._client_node.network_encryption_key, input_tensor
            )
            input_tensor_type = TensorType.CipherText

        return linear(
            self._client_node,
            input_tensor,
            self._weights,
            self._bias,
            self._scaling_factor,
            input_tensor_type,
            self._weights_tensor_type,
            self._bias_tensor_type,
        )

    def map_back(
        self,
        input_tensor: GenericTensor[CipherText] | GenericTensor[PlainText],
        input_tensor_type: TensorType = TensorType.CipherText,
    ) -> Tensor:
        """Decrypt the output tensor and//or scale it down.

        Args:
            input_tensor (GenericTensor[CipherText]|GenericTensor[PlainText]): The input tensor.
            input_tensor_type (TensorType, optional): The tensor type of the input tensor. Defaults to TensorType.CipherText.

        Returns:
            Tensor: The final output tensor.
        """
        if input_tensor_type == TensorType.CipherText:
            input_tensor = perform_tensor_decryption(
                self._client_node, input_tensor
            )

        return scale_down(
            self._client_node.cryptosystem,
            input_tensor,
            self._scaling_factor,
            2,
        )
