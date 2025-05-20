
from __future__ import annotations

from enum import Enum
from typing import List

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
    REENCRYPT = ...
    ADD = ...
    SUBTRACT = ...
    MULTIPLY = ...
    DIVIDE = ...
    LT = ...
    GT = ...
    EQ = ...
    NEQ = ...
    LTEQ = ...
    GTEQ = ...

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
        data (bytes): The data associated with the response.
    """

    def __init__(self, status: ComputeResponseStatus, data: bytes) -> None:
        """
        Initialize a ComputeResponse.

        Args:
            status (ComputeResponseStatus): The status of the response.
            data (bytes): The data associated with the response.
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
    def data(self) -> bytes:
        """
        Get the data associated with the response.

        Returns:
            bytes: The data associated with the response.
        """
        ...

    @data.setter
    def data(self, data: bytes) -> None:
        """
        Set the data associated with the response.

        Args:
            data (bytes): The new data for the response.
        """
        ...

    def to_string(self) -> bytes:
        """
        Convert the ComputeResponse to its string representation.

        Returns:
            bytes: Binary string representation of the ComputeResponse.
        """
        ...

    @staticmethod
    def from_string(data: bytes) -> "ComputeResponse":
        """
        Create a ComputeResponse from its binary string representation.

        Args:
            data (bytes): The serialized ComputeResponse.

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
    def data(self) -> bytes:
        """
        Get the data of the operand.

        Returns:
            bytes: The data of the operand.
        """
        ...

    @data.setter
    def data(self, data: bytes) -> None:
        """
        Set the data of the operand.

        Args:
            data (bytes): The new data for the operand.
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

    def to_string(self) -> bytes:
        """
        Convert the ComputeRequest to its string representation.

        Returns:
            bytes: The string representation of the ComputeRequest.
        """
        ...

    @staticmethod
    def from_string(data: bytes) -> "ComputeRequest":
        """
        Create a ComputeRequest from its string representation.

        Args:
            data (bytes): The serialized ComputeRequest.

        Returns:
            ComputeRequest: The deserialized ComputeRequest object.
        """
        ...
