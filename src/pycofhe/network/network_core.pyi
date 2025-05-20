"""Typing stubs for the network module"""

from __future__ import annotations

from enum import Enum
from typing import List, overload, Generic

from pycofhe.cryptosystems.cpu_cryptosystem_core import (
    CPUCryptoSystemSecretKey,
    CPUCryptoSystemSecretKeyShare,
    CPUCryptoSystemPublicKey,
    CPUCryptoSystemPlainText,
    CPUCryptoSystemCipherText,
    CPUCryptoSystemPartialDecryptionResult,
)
from pycofhe.cryptosystems.cryptosystem import (
    CipherText,
    CryptoSystem,
    PartialDecryptionResult,
    PlainText,
    PublicKey,
    SecretKey,
    SecretKeyShare,
)

from pycofhe.network.binary_scheme_core import *
from pycofhe.network.native_transfer_func import *
from pycofhe.network.network_details import *
from pycofhe.network.reencryptor import *
from pycofhe.network.request_response import *
from pycofhe.network.compute_request_response import *
from pycofhe.network.setup_node_request_response import *

class Client:
    """
    A client for communicating with the network.
    """

    def __init__(
        self,
        address: str,
        port: str,
        cert: str = "./server.pem",
        keep_session_alive: bool = False,
    ):
        """
        Create a client for the given address and port.

        Args:
            address (str): The address of the server.
            port (str): The port of the server.
            cert (str): The certificate file for the client. Default is "./server.pem".
            keep_session_alive (bool): Whether to keep the session alive. Default is False.
        """
        ...

    @overload
    def run(self, request: SetupNodeRequest) -> SetupNodeResponse:
        """
        Run the client with the given type and request.

        Args:
            request (SetupNodeRequest): The request to run.

        Returns:
            SetupNodeResponse: The response to the request.
        """
        ...

    @overload
    def run(self, request: ComputeRequest) -> ComputeResponse:
        """
        Run the client with the given type and request.

        Args:
            request (ComputeRequest): The request to run.

        Returns:
            ComputeResponse: The response to the request.
        """
        ...

class ClientNode(
    Generic[
        SecretKey,
        SecretKeyShare,
        PublicKey,
        PlainText,
        CipherText,
        PartialDecryptionResult,
        PKCEncryptor,
    ]
):
    """
    A client node for the cryptosystem.
    """

    def compute(self, request: ComputeRequest) -> ComputeResponse:
        """
        Compute the given request.

        Args:
            request (ComputeRequest): The request to compute.

        Returns:
            ComputeResponse: The response to the request.
        """
        ...

    @property
    def cryptosystem(
        self,
    ) -> CryptoSystem[
        SecretKey,
        SecretKeyShare,
        PublicKey,
        PlainText,
        CipherText,
        PartialDecryptionResult,
    ]:
        """
        Get the cryptosystem of the client node.

        Returns:
            CryptoSystem: The cryptosystem of the client node.
        """
        ...

    @property
    def network_encryption_key(self) -> PublicKey:
        """
        Get the network encryption key of the client node.

        Returns:
            PublicKey: The network encryption key of the client node.
        """
        ...

    @property
    def reencryptor(
        self,
    ) -> Reencryptor[
        PKCEncryptor,
        SecretKey,
        SecretKeyShare,
        PublicKey,
        PlainText,
        CipherText,
        PartialDecryptionResult,
    ]:
        """
        Get the reencryptor of the client node.

        Returns:
            Reencryptor: The reencryptor of the client node.
        """
        ...

    @property
    def network_details(self) -> NetworkDetails:
        """
        Get the network details of the client node.

        Returns:
            NetworkDetails: The network details of the client node.
        """
        ...

CPUCryptoSystemClientNode = ClientNode[
    CPUCryptoSystemSecretKey,
    CPUCryptoSystemSecretKeyShare,
    CPUCryptoSystemPublicKey,
    CPUCryptoSystemPlainText,
    CPUCryptoSystemCipherText,
    CPUCryptoSystemPartialDecryptionResult,
    RSAPKCEncryptor,
]

@overload
def make_cpu_cryptosystem_client_node(
    client_ip: str,
    client_port: str,
    setup_ip: str,
    setup_port: str,
    cert_file: str = "./server.pem",
) -> CPUCryptoSystemClientNode:
    """
    Create a client node for the cpu cryptosystem.

    Args:
        client_ip (str): The IP address of the client node.
        client_port (str): The port of the client node.
        setup_ip (str): The IP address of the setup node.
        setup_port (str): The port of the setup node.
        cert_file (str): The certificate file for the client node. Default is "./server.pem".

    Returns:
        ClientNode: A client node for the cpu cryptosystem.
    """
    ...

@overload
def make_cpu_cryptosystem_client_node(
    network_details: NetworkDetails,
    cert_file: str = "./server.pem",
) -> CPUCryptoSystemClientNode:
    """
    Create a client node for the cpu cryptosystem.

    Args:
        network_details (NetworkDetails): The network details for the client node.
        cert_file (str): The certificate file for the client node. Default is "./server.pem".

    Returns:
        ClientNode: A client node for the cpu cryptosystem.
    """
    ...
