"""Typing stubs for the NetworkDetails and related class."""

from __future__ import annotations

from typing import List, overload

from enum import Enum

class NodeType(Enum):
    """Enum for different types of nodes."""

    SETUP_NODE = ...
    CoFHE_NODE = ...
    COMPUTE_NODE = ...
    CLIENT_NODE = ...

class NodeDetails:
    """Class to hold the details of a node."""

    @overload
    def __init__(self) -> None:
        """Initialize the NodeDetails class."""
        ...

    @overload
    def __init__(self, ip: str, port: str, node_type: NodeType) -> None:
        """Initialize the NodeDetails class.

        Args:
            ip (str): The IP address of the node.
            port (str): The port number of the node.
            type (NodeType): The type of the node.
        """
        ...

    @property
    def ip(self) -> str:
        """Get the IP address of the node."""
        ...

    @ip.setter
    def ip(self, ip: str) -> None:
        """Set the IP address of the node."""
        ...

    @property
    def port(self) -> int:
        """Get the port number of the node."""
        ...

    @port.setter
    def port(self, port: int) -> None:
        """Set the port number of the node."""
        ...

    @property
    def node_type(self) -> NodeType:
        """Get the type of the node."""
        ...

    @node_type.setter
    def node_type(self, node_type: NodeType) -> None:
        """Set the type of the node."""
        ...

class ReencryptorType(Enum):
    """Enum for different types of reencryptors."""

    RSA = ...

class ReencryptorDetails:
    """Class to hold the details of a reencryptor."""

    @overload
    def __init__(self) -> None:
        """Initialize the ReencryptorDetails class."""
        ...

    @overload
    def __init__(
        self, reencryptor_type: ReencryptorType, key_size: int
    ) -> None:
        """Initialize the ReencryptorDetails class.

        Args:
            reencryptor_type (ReencryptorType): The type of the reencryptor.
            key_size (int): The key size of the reencryptor.
        """
        ...

    @property
    def reencryptor_type(self) -> ReencryptorType:
        """Get the type of the reencryptor."""
        ...

    @reencryptor_type.setter
    def reencryptor_type(self, reencryptor_type: ReencryptorType) -> None:
        """Set the type of the reencryptor."""
        ...

    @property
    def key_size(self) -> int:
        """Get the key size of the reencryptor."""
        ...

    @key_size.setter
    def key_size(self, key_size: int) -> None:
        """Set the key size of the reencryptor."""
        ...

class CryptoSystemType(Enum):
    """Enum for different types of cryptosystems."""

    CoFHE_CPU = ...

class CryptoSystemDetails:
    """Class to hold the details of a cryptosystem."""

    @overload
    def __init__(self) -> None:
        """Initialize the CryptoSystemDetails class."""
        ...

    @overload
    def __init__(
        self,
        cryptosystem_type: CryptoSystemType,
        public_key: bytes,
        security_level: int,
        k: int,
        threshold: int,
        total_nodes: int,
        N:str
    ) -> None:
        """Initialize the CryptoSystemDetails class.

        Args:
            cryptosystem_type (CryptoSystemType): The type of the cryptosystem.
            public_key (bytes): The network encryption key.
            security_level (int): The security level of the cryptosystem.
            k (int): The number of shares.
            threshold (int): The threshold for secret sharing.
            total_nodes (int): The total number of nodes.
            N (str): The N value for the cryptosystem.
        """
        ...

    @property
    def type(self) -> CryptoSystemType:
        """Get the type of the cryptosystem."""
        ...

    @type.setter
    def type(self, cryptosystem_type: CryptoSystemType) -> None:
        """Set the type of the cryptosystem."""
        ...

    @property
    def public_key(self) -> bytes:
        """Get the network public key."""
        ...

    @public_key.setter
    def public_key(self, public_key: bytes) -> None:
        """Set the network public key."""
        ...

    @property
    def security_level(self) -> int:
        """Get the security level of the cryptosystem."""
        ...

    @security_level.setter
    def security_level(self, security_level: int) -> None:
        """Set the security level of the cryptosystem."""
        ...

    @property
    def k(self) -> int:
        """Get the number of shares."""
        ...

    @k.setter
    def k(self, k: int) -> None:
        """Set the number of shares."""
        ...

    @property
    def threshold(self) -> int:
        """Get the threshold for secret sharing."""
        ...

    @threshold.setter
    def threshold(self, threshold: int) -> None:
        """Set the threshold for secret sharing."""
        ...

    @property
    def total_nodes(self) -> int:
        """Get the total number of nodes."""
        ...

    @total_nodes.setter
    def total_nodes(self, total_nodes: int) -> None:
        """Set the total number of nodes."""
        ...

    @property
    def N(self) -> str:
        """Get the N value for the cryptosystem."""
        ...

    @N.setter
    def N(self, N: str) -> None:
        """Set the N value for the cryptosystem."""
        ...

class NetworkDetails:
    """Class to hold the details of the network."""

    @overload
    def __init__(self) -> None:
        """Initialize the NetworkDetails class."""
        ...

    @overload
    def __init__(
        self,
        self_node: NodeDetails,
        nodes: List[NodeDetails],
        cryptosystem_details: CryptoSystemDetails,
        secret_key_shares: List[bytes],
        reencryptor_details: ReencryptorDetails,
    ) -> None:
        """Initialize the NetworkDetails class.

        Args:
            self_node (NodeDetails): The details of the current node.
            nodes (List[NodeDetails]): The details of all nodes in the network.
            cryptosystem_details (CryptoSystemDetails): The details of the cryptosystem.
            secret_key_shares (List[bytes]): The secret key shares for each node.
            reencryptor_details (ReencryptorDetails): The details of the reencryptor.
        """
        ...

    @property
    def self_node(self) -> NodeDetails:
        """Get the details of the current node."""
        ...

    @property
    def nodes(self) -> List[NodeDetails]:
        """Get the details of all nodes in the network."""
        ...

    @property
    def cryptosystem_details(self) -> CryptoSystemDetails:
        """Get the details of the cryptosystem."""
        ...

    @property
    def secret_key_shares(self) -> List[str]:
        """Get the secret key shares for each node."""
        ...

    @property
    def reencryptor_details(self) -> ReencryptorDetails:
        """Get the details of the reencryptor."""
        ...

    def to_string(self) -> str:
        """Convert the NetworkDetails object to a string"""
        ...

    @classmethod
    def from_string(cls, data: str) -> NetworkDetails:
        """Create a NetworkDetails object from a string"""
        ...
