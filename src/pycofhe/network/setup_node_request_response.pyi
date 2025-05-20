from __future__ import annotations

from enum import Enum

class SetupNodeRequestType(Enum):
    """Enum for SetupNodeRequest types."""

    BEAVERS_TRIPLET_REQUEST = ...
    COMPARISON_PAIR_REQUEST = ...
    JOIN_AS_NODE_REQUEST = ...
    NetworkDetailsRequest = ...

class SetupNodeResponseStatus(Enum):
    """Enum for SetupNodeResponse status."""

    OK = ...
    ERROR = ...

class SetupNodeRequest:
    """Class for SetupNodeRequest."""

    def __init__(self, type: SetupNodeRequestType, data: bytes) -> None:
        """
        Initialize SetupNodeRequest with type and data.

        Args:
            type (SetupNodeRequestType): The type of the request.
            data (bytes): The data of the request.
        """
        ...

    @property
    def type(self) -> SetupNodeRequestType:
        """Get the type of the request."""
        ...

    @type.setter
    def type(self, value: SetupNodeRequestType) -> None:
        """Set the type of the request."""
        ...

    @property
    def data_size(self) -> int:
        """Get the size of the data."""
        ...

    @data_size.setter
    def data_size(self, value: int) -> None:
        """Set the size of the data."""
        ...

    @property
    def data(self) -> bytes:
        """Get the data of the request."""
        ...

    @data.setter
    def data(self, value: bytes) -> None:
        """Set the data of the request."""
        ...

    def to_string(self) -> bytes:
        """Convert the request to a string."""
        ...

    @staticmethod
    def from_string(data: bytes) -> SetupNodeRequest:
        """Create a SetupNodeRequest from a string."""
        ...

class SetupNodeResponse:
    """Class for SetupNodeResponse."""

    def __init__(self, status: SetupNodeResponseStatus, data: bytes) -> None:
        """
        Initialize SetupNodeResponse with status and data.

        Args:
            status (SetupNodeResponseStatus): The status of the response.
            data (bytes): The data of the response.
        """
        ...

    @property
    def status(self) -> SetupNodeResponseStatus:
        """Get the status of the response."""
        ...

    @status.setter
    def status(self, value: SetupNodeResponseStatus) -> None:
        """Set the status of the response."""
        ...

    @property
    def data_size(self) -> int:
        """Get the size of the data."""
        ...

    @data_size.setter
    def data_size(self, value: int) -> None:
        """Set the size of the data."""
        ...

    @property
    def data(self) -> bytes:
        """Get the data of the response."""
        ...

    @data.setter
    def data(self, value: bytes) -> None:
        """Set the data of the response."""
        ...

    def to_string(self) -> bytes:
        """Convert the response to a string."""
        ...

    @staticmethod
    def from_string(data: bytes) -> SetupNodeResponse:
        """Create a SetupNodeResponse from a string."""
        ...

class NetworkDetailsRequestType(Enum):
    """Enum for NetworkDetailsRequest types."""

    GET = ...
    SET = ...

class NetworkDetailsResponseStatus(Enum):
    """Enum for NetworkDetailsResponse status."""

    OK = ...
    ERROR = ...

class NetworkDetailsRequest:
    """Class for NetworkDetailsRequest."""

    def __init__(self, type: NetworkDetailsRequestType, data: bytes) -> None:
        """
        Initialize NetworkDetailsRequest with type and data.

        Args:
            type (NetworkDetailsRequestType): The type of the request.
            data (bytes): The data of the request.
        """
        ...

    @property
    def type(self) -> NetworkDetailsRequestType:
        """Get the type of the request."""
        ...

    @type.setter
    def type(self, value: NetworkDetailsRequestType) -> None:
        """Set the type of the request."""
        ...

    @property
    def data_size(self) -> int:
        """Get the size of the data."""
        ...

    @data_size.setter
    def data_size(self, value: int) -> None:
        """Set the size of the data."""
        ...

    @property
    def data(self) -> bytes:
        """Get the data of the request."""
        ...

    @data.setter
    def data(self, value: bytes) -> None:
        """Set the data of the request."""
        ...

    def to_string(self) -> bytes:
        """Convert the request to a string."""
        ...

    @staticmethod
    def from_string(data: bytes) -> NetworkDetailsRequest:
        """Create a NetworkDetailsRequest from a string."""
        ...

class NetworkDetailsResponse:
    """Class for NetworkDetailsResponse."""

    def __init__(
        self, status: NetworkDetailsResponseStatus, data: bytes
    ) -> None:
        """
        Initialize NetworkDetailsResponse with status and data.

        Args:
            status (NetworkDetailsResponseStatus): The status of the response.
            data (bytes): The data of the response.
        """
        ...

    @property
    def status(self) -> NetworkDetailsResponseStatus:
        """Get the status of the response."""
        ...

    @status.setter
    def status(self, value: NetworkDetailsResponseStatus) -> None:
        """Set the status of the response."""
        ...

    @property
    def data_size(self) -> int:
        """Get the size of the data."""
        ...

    @data_size.setter
    def data_size(self, value: int) -> None:
        """Set the size of the data."""
        ...

    @property
    def data(self) -> bytes:
        """Get the data of the response."""
        ...

    @data.setter
    def data(self, value: bytes) -> None:
        """Set the data of the response."""
        ...

    def to_string(self) -> bytes:
        """Convert the response to a string."""
        ...

    @staticmethod
    def from_string(data: bytes) -> NetworkDetailsResponse:
        """Create a NetworkDetailsResponse from a string."""
        ...
