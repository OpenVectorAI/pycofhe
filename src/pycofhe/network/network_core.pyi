"""Typing stubs for the network module"""

from __future__ import annotations

from enum import Enum
from typing import List, TYPE_CHECKING, overload

if TYPE_CHECKING:
    from pycofhe.network.binary_scheme_core import *

from pycofhe.cpu_cryptosystem import CPUCryptoSystem, PublicKey

# pylint: disable=unused-argument,unnecessary-ellipsis

class ComputeResponseStatus(Enum):
    """
    Enumeration for the status of a ComputeResponse.
    """

    OK = ...
    ERROR = ...

class ComputeOperationType(Enum):
    """
    Enumeration for the type of compute operation.
    """

    UNARY = ...
    BINARY = ...
    TERNARY = ...

class ComputeOperation(Enum):
    """
    Enumeration for the compute operations.
    """

    DECRYPT = ...
    ADD = ...
    SUBTRACT = ...
    MULTIPLY = ...
    DIVIDE = ...

class DataType(Enum):
    """
    Enumeration for the data type in a compute operation operand.
    """

    SINGLE = ...
    TENSOR = ...
    TENSOR_ID = ...

class DataEncryptionType(Enum):
    """
    Enumeration for the data encryption type in a compute operation operand.
    """

    PLAINTEXT = ...
    CIPHERTEXT = ...

class ComputeResponse:
    """
    Represents a compute response.

    Attributes:
        status (ComputeResponseStatus): The status of the compute response.
        data (str): The data associated with the response.
        data_bytes (bytes): The binary data associated with the response.
    """

    def __init__(self, status: ComputeResponseStatus, data: str) -> None:
        """
        Initialize a ComputeResponse.

        Args:
            status (ComputeResponseStatus): The status of the response.
            data (str): The data associated with the response.
        """
        ...

    @property
    def status(self) -> ComputeResponseStatus:
        """
        Get the status of the compute response.

        Returns:
            ComputeResponseStatus: The status of the compute response.
        """
        ...

    @status.setter
    def status(self, status: ComputeResponseStatus) -> None:
        """
        Set the status of the compute response.

        Args:
            status (ComputeResponseStatus): The new status of the response.
        """
        ...

    @property
    def data(self) -> str:
        """
        Get the data associated with the response.

        Returns:
            str: The data associated with the response.
        """
        ...

    @data.setter
    def data(self, data: str) -> None:
        """
        Set the data associated with the response.

        Args:
            data (str): The new data for the response.
        """
        ...

    @property
    def data_bytes(self) -> bytes:
        """
        Get the binary data associated with the response.

        Returns:
            bytes: The binary data associated with the response.
        """
        ...

    @data_bytes.setter
    def data_bytes(self, data: bytes) -> None:
        """
        Set the binary data associated with the response.

        Args:
            data (bytes): The new binary data for the response.
        """
        ...

    def to_string(self) -> str:
        """
        Convert the ComputeResponse to its string representation.

        Returns:
            str: The string representation of the ComputeResponse.
        """
        ...

    @staticmethod
    def from_string(data: str) -> "ComputeResponse":
        """
        Create a ComputeResponse from its string representation.

        Args:
            data (str): The serialized ComputeResponse.

        Returns:
            ComputeResponse: The deserialized ComputeResponse object.
        """
        ...

class ComputeOperationOperand:
    """
    Represents an operand in a compute operation instance.

    Attributes:
        data_type (DataType): The data type of the operand.
        encryption_type (DataEncryptionType): The encryption type of the operand.
        data (str): The data of the operand.
    """

    @overload
    def __init__(
        self,
        data_type: DataType,
        encryption_type: DataEncryptionType,
        data: str,
    ) -> None:
        """
        Initialize a ComputeOperationOperand.

        Args:
            data_type (DataType): The data type of the operand.
            encryption_type (DataEncryptionType): The encryption type of the operand.
            data (str): The data of the operand.
        """
        ...

    @overload
    def __init__(
        self,
        data_type: DataType,
        encryption_type: DataEncryptionType,
        data: bytes,
    ) -> None:
        """
        Initialize a ComputeOperationOperand.

        Args:
            data_type (DataType): The data type of the operand.
            encryption_type (DataEncryptionType): The encryption type of the operand.
            data (bytes): The binary data of the operand.
        """
        ...

    @property
    def data_type(self) -> DataType:
        """
        Get the data type of the operand.

        Returns:
            DataType: The data type of the operand.
        """
        ...

    @data_type.setter
    def data_type(self, data_type: DataType) -> None:
        """
        Set the data type of the operand.

        Args:
            data_type (DataType): The new data type of the operand.
        """
        ...

    @property
    def encryption_type(self) -> DataEncryptionType:
        """
        Get the encryption type of the operand.

        Returns:
            DataEncryptionType: The encryption type of the operand.
        """
        ...

    @encryption_type.setter
    def encryption_type(self, encryption_type: DataEncryptionType) -> None:
        """
        Set the encryption type of the operand.

        Args:
            encryption_type (DataEncryptionType): The new encryption type of the operand.
        """
        ...

    @property
    def data(self) -> str:
        """
        Get the data of the operand.

        Returns:
            str: The data of the operand.
        """
        ...

    @data.setter
    def data(self, data: str) -> None:
        """
        Set the data of the operand.

        Args:
            data (str): The new data for the operand.
        """
        ...

    @property
    def data_bytes(self) -> bytes:
        """
        Get the binary data of the operand.

        Returns:
            bytes: The binary data of the operand.
        """
        ...

    @data_bytes.setter
    def data_bytes(self, data: bytes) -> None:
        """
        Set the binary data of the operand.

        Args:
            data (bytes): The new binary data for the operand.
        """
        ...

    def to_string(self) -> str:
        """
        Convert the ComputeOperationOperand to its string representation.

        Returns:
            str: The string representation of the ComputeOperationOperand.
        """
        ...

    @staticmethod
    @overload
    def from_string(data: str) -> "ComputeOperationOperand":
        """
        Create a ComputeOperationOperand from its string representation.

        Args:
            data (str): The serialized ComputeOperationOperand.

        Returns:
            ComputeOperationOperand: The deserialized ComputeOperationOperand object.
        """
        ...

    @staticmethod
    @overload
    def from_string(data: str, index: int) -> "ComputeOperationOperand":
        """
        Create a ComputeOperationOperand from its string representation with an additional index.

        Args:
            data (str): The serialized ComputeOperationOperand.
            index (int): An additional index parameter.

        Returns:
            ComputeOperationOperand: The deserialized ComputeOperationOperand object.
        """
        ...

class ComputeOperationInstance:
    """
    Represents an instance of a compute operation.

    Attributes:
        operation_type (ComputeOperationType): The type of the compute operation.
        operation (ComputeOperation): The compute operation.
        operands (List[ComputeOperationOperand]): The list of operands for the compute operation.
    """

    def __init__(
        self,
        operation_type: ComputeOperationType,
        operation: ComputeOperation,
        operands: List[ComputeOperationOperand],
    ) -> None:
        """
        Initialize a ComputeOperationInstance.

        Args:
            operation_type (ComputeOperationType): The type of the compute operation.
            operation (ComputeOperation): The compute operation.
            operands (List[ComputeOperationOperand]): The list of operands.
        """
        ...

    @property
    def operation_type(self) -> ComputeOperationType:
        """
        Get the type of the compute operation.

        Returns:
            ComputeOperationType: The type of the compute operation.
        """
        ...

    @operation_type.setter
    def operation_type(self, operation_type: ComputeOperationType) -> None:
        """
        Set the type of the compute operation.

        Args:
            operation_type (ComputeOperationType): The new type of the compute operation.
        """
        ...

    @property
    def operation(self) -> ComputeOperation:
        """
        Get the compute operation.

        Returns:
            ComputeOperation: The compute operation.
        """
        ...

    @operation.setter
    def operation(self, operation: ComputeOperation) -> None:
        """
        Set the compute operation.

        Args:
            operation (ComputeOperation): The new compute operation.
        """
        ...

    @property
    def operands(self) -> List[ComputeOperationOperand]:
        """
        Get the list of operands for the compute operation.

        Returns:
            List[ComputeOperationOperand]: The list of operands.
        """
        ...

    def to_string(self) -> str:
        """
        Convert the ComputeOperationInstance to its string representation.

        Returns:
            str: The string representation of the ComputeOperationInstance.
        """
        ...

    @staticmethod
    def from_string(data: str) -> "ComputeOperationInstance":
        """
        Create a ComputeOperationInstance from its string representation.

        Args:
            data (str): The serialized ComputeOperationInstance.

        Returns:
            ComputeOperationInstance: The deserialized ComputeOperationInstance object.
        """
        ...

class ComputeRequest:
    """
    Represents a compute request.

    Attributes:
        operation (ComputeOperationInstance): The compute operation instance.
    """

    def __init__(self, operation: ComputeOperationInstance) -> None:
        """
        Initialize a ComputeRequest.

        Args:
            operation (ComputeOperationInstance): The compute operation instance.
        """
        ...

    @property
    def operation(self) -> ComputeOperationInstance:
        """
        Get the compute operation instance.

        Returns:
            ComputeOperationInstance: The compute operation instance.
        """
        ...

    def to_string(self) -> str:
        """
        Convert the ComputeRequest to its string representation.

        Returns:
            str: The string representation of the ComputeRequest.
        """
        ...

    @staticmethod
    def from_string(data: str) -> "ComputeRequest":
        """
        Create a ComputeRequest from its string representation.

        Args:
            data (str): The serialized ComputeRequest.

        Returns:
            ComputeRequest: The deserialized ComputeRequest object.
        """
        ...

class CPUCryptoSystemClientNode:
    """
    A client node for the CPU cryptosystem.
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
    def cryptosystem(self) -> CPUCryptoSystem:
        """
        Get the cryptosystem of the client node.

        Returns:
            CPUCryptoSystem: The cryptosystem of the client node.
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

def make_cpucryptosystem_client_node(
    client_ip: str,
    client_port: str,
    setup_ip: str,
    setup_port: str,
    cert_file: str = "./server.pem",
) -> CPUCryptoSystemClientNode:
    """
    Create a client node for the CPU cryptosystem.

    Args:
        client_ip (str): The IP address of the client node.
        client_port (str): The port of the client node.
        setup_ip (str): The IP address of the setup node.
        setup_port (str): The port of the setup node.
        cert_file (str): The certificate file for the client node. Default is "./server.pem".

    Returns:
        CPUCryptoSystemClientNode: A client node for the CPU cryptosystem.
    """
    ...
