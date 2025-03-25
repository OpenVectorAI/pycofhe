from __future__ import annotations

from pycofhe.cpu_cryptosystem import (
    CPUCryptoSystemCipherTextTensor,
    CPUCryptoSystemPlainTextTensor,
)
from pycofhe.network import CPUCryptoSystemClientNode, perform_tensor_decryption
from pycofhe.nn.functional import linear
from pycofhe.tensor import Tensor
from pycofhe.utils import scale_down, scale_up

from .module import Module


class Linear(Module):
    """Linear module for neural networks.

    This module performs a linear operation on the input tensor using the weights tensor and bias tensor.
    The output is calculated as follows:
        output = input * weights + bias
    """

    __slots__ = (
        "_input_size",
        "_output_size",
        "_weights",
        "_bias",
        "_scaling_factor",
    )

    _input_size: int
    _output_size: int
    _weights: CPUCryptoSystemCipherTextTensor | CPUCryptoSystemPlainTextTensor
    _bias: (
        CPUCryptoSystemCipherTextTensor | CPUCryptoSystemPlainTextTensor | None
    )
    _scaling_factor: int

    def __init__(
        self,
        client_node: CPUCryptoSystemClientNode,
        input_size: int,
        output_size: int,
        weights: (
            Tensor
            | CPUCryptoSystemCipherTextTensor
            | CPUCryptoSystemPlainTextTensor
        ),
        bias: (
            Tensor
            | CPUCryptoSystemCipherTextTensor
            | CPUCryptoSystemPlainTextTensor
            | None
        ) = None,
        encrypt_weights: bool = True,
        encrypt_bias: bool = True,
        scaling_factor: int = 1,
    ) -> None:
        """Initialize the Linear module.

        Args:
            client_node (CPUCryptoSystemClientNode): The client node.
            input_size (int): The input size.
            output_size (int): The output size.
            weights (Tensor|CPUCryptoSystemCipherTextTensor|CPUCryptoSystemPlainTextTensor): The weights tensor.
            bias (Tensor|CPUCryptoSystemCipherTextTensor|CPUCryptoSystemPlainTextTensor|None, optional): The bias tensor. Defaults to None.
            encrypt_weights (bool, optional): Encrypt the weights tensor. Defaults to True.
            encrypt_bias (bool, optional): Encrypt the bias tensor. Defaults to True. If the weights tensor is encrypted, the bias tensor will be encrypted.
            scaling_factor (int, optional): The scaling factor. Defaults to 1.
        """
        super().__init__(client_node)

        self._input_size = input_size
        self._output_size = output_size
        self._scaling_factor = scaling_factor

        if isinstance(weights, Tensor):
            weights = scale_up(
                    self._client_node.cryptosystem,
                    weights,
                    scaling_factor,
                )
        if isinstance(bias, Tensor):
            bias = scale_up(
                    self._client_node.cryptosystem,
                    bias,
                    scaling_factor**2,
                )
        
        if encrypt_weights:
            weights = self._client_node.cryptosystem.encrypt_tensor(
                self._client_node.network_encryption_key, weights
            )

        if encrypt_bias and bias is not None:
            bias = self._client_node.cryptosystem.encrypt_tensor(
                self._client_node.network_encryption_key, bias
            )
        
        self._weights = weights
        self._bias = bias

    def forward(
        self,
        input_tensor: (
            CPUCryptoSystemCipherTextTensor
            | CPUCryptoSystemPlainTextTensor
            | Tensor
        ),
        *args,
        **kwargs,
    ) -> CPUCryptoSystemCipherTextTensor | CPUCryptoSystemPlainTextTensor:
        """Perform the forward operation.

        Args:
            input_tensor (CPUCryptoSystemCipherTextTensor|CPUCryptoSystemPlainTextTensor|Tensor): The input tensor. Will be encrypted if it is a plaintext tensor.
                Pass `encrypt_input=False` to disable encryption using kwargs.

        Returns:
            CPUCryptoSystemCipherTextTensor|CPUCryptoSystemPlainTextTensor: The output tensor.
        """
        if isinstance(input_tensor, Tensor):
            input_tensor = scale_up(
                self._client_node.cryptosystem,
                input_tensor,
                self._scaling_factor,
            )

        encrypt_input = kwargs.get("encrypt_input", True)

        if encrypt_input and isinstance(
            input_tensor, CPUCryptoSystemPlainTextTensor
        ):
            input_tensor = self._client_node.cryptosystem.encrypt_tensor(
                self._client_node.network_encryption_key, input_tensor
            )

        return linear(
            self._client_node,
            input_tensor,
            self._weights,
            self._bias,
            self._scaling_factor,
        )

    def map_back(self, input_tensor: CPUCryptoSystemCipherTextTensor|CPUCryptoSystemPlainTextTensor) -> Tensor:
        """Decrypt the output tensor and//or scale it down.

        Args:
            input_tensor (CPUCryptoSystemCipherTextTensor|CPUCryptoSystemPlainTextTensor): The input tensor.

        Returns:
            Tensor: The final output tensor.
        """
        if isinstance(input_tensor, CPUCryptoSystemCipherTextTensor):
            input_tensor = perform_tensor_decryption(self._client_node, input_tensor)

        return scale_down(
            self._client_node.cryptosystem,
            input_tensor,
            self._scaling_factor,
            2
        )