from __future__ import annotations

from enum import Enum

class ProtocolVersion(Enum):
    """Protocol version enum."""

    V1 = ...

class ServiceType(Enum):
    """Service type enum."""

    COMPUTE_REQUEST = ...
    COFHE_REQUEST = ...
    SETUP_REQUEST = ...

class ResponseStatus(Enum):
    """Response status enum."""

    OK = ...
    ERROR = ...

class ResponseHeader:
    """Response header class."""

    def __init__(
        self,
        protocol_version: ProtocolVersion,
        service_type: ServiceType,
        status: ResponseStatus,
        data_size: int,
    ):
        """Initialize the response header with protocol version, service type, status, and data size."""
        ...

    @property
    def protocol_version(self) -> ProtocolVersion:
        """Get the protocol version."""
        ...

    @protocol_version.setter
    def protocol_version(self, value: ProtocolVersion):
        """Set the protocol version."""
        ...

    @property
    def type(self) -> ServiceType:
        """Get the service type."""
        ...

    @type.setter
    def type(self, value: ServiceType):
        """Set the service type."""
        ...

    @property
    def status(self) -> ResponseStatus:
        """Get the response status."""
        ...

    @status.setter
    def status(self, value: ResponseStatus):
        """Set the response status."""
        ...

    @property
    def data_size(self) -> int:
        """Get the data size."""
        ...

    @data_size.setter
    def data_size(self, value: int):
        """Set the data size."""
        ...

class Response:
    """Response class."""

    def __init__(
        self,
        protocol_version: ProtocolVersion,
        service_type: ServiceType,
        status: ResponseStatus,
        data: bytes,
    ):
        """Initialize the response with protocol version, service type, status, and data."""
        ...

    @property
    def header(self) -> ResponseHeader:
        """Get the response header."""
        ...

    @header.setter
    def header(self, value: ResponseHeader):
        """Set the response header."""
        ...

    @property
    def protocol_version(self) -> ProtocolVersion:
        """Get the protocol version."""
        ...

    @protocol_version.setter
    def protocol_version(self, value: ProtocolVersion):
        """Set the protocol version."""
        ...

    @property
    def type(self) -> ServiceType:
        """Get the service type."""
        ...

    @type.setter
    def type(self, value: ServiceType):
        """Set the service type."""
        ...

    @property
    def status(self) -> ResponseStatus:
        """Get the response status."""
        ...

    @status.setter
    def status(self, value: ResponseStatus):
        """Set the response status."""
        ...

    @property
    def data_size(self) -> int:
        """Get the data size."""
        ...

    @data_size.setter
    def data_size(self, value: int):
        """Set the data size."""
        ...

    @property
    def data(self) -> bytes:
        """Get the response data."""
        ...

    @data.setter
    def data(self, value: bytes):
        """Set the response data."""
        ...

    def to_string(self) -> bytes:
        """Convert the response to a string."""
        ...

    @staticmethod
    def from_string(data: bytes) -> Response:
        """Create a response from a string."""
        ...

class RequestHeader:
    """Request header class."""

    def __init__(
        self,
        protocol_version: ProtocolVersion,
        service_type: ServiceType,
        data_size: int,
    ):
        """Initialize the request header with protocol version, service type, and data size."""
        ...

    @property
    def protocol_version(self) -> ProtocolVersion:
        """Get the protocol version."""
        ...

    @protocol_version.setter
    def protocol_version(self, value: ProtocolVersion):
        """Set the protocol version."""
        ...

    @property
    def type(self) -> ServiceType:
        """Get the service type."""
        ...

    @type.setter
    def type(self, value: ServiceType):
        """Set the service type."""
        ...

    @property
    def data_size(self) -> int:
        """Get the data size."""
        ...

    @data_size.setter
    def data_size(self, value: int):
        """Set the data size."""
        ...

class Request:
    """Request class."""

    def __init__(
        self,
        protocol_version: ProtocolVersion,
        service_type: ServiceType,
        data: bytes,
    ):
        """Initialize the request with protocol version, service type, and data."""
        ...

    @property
    def header(self) -> RequestHeader:
        """Get the request header."""
        ...

    @header.setter
    def header(self, value: RequestHeader):
        """Set the request header."""
        ...

    @property
    def protocol_version(self) -> ProtocolVersion:
        """Get the protocol version."""
        ...

    @protocol_version.setter
    def protocol_version(self, value: ProtocolVersion):
        """Set the protocol version."""
        ...

    @property
    def type(self) -> ServiceType:
        """Get the service type."""
        ...

    @type.setter
    def type(self, value: ServiceType):
        """Set the service type."""
        ...

    @property
    def data_size(self) -> int:
        """Get the data size."""
        ...

    @data_size.setter
    def data_size(self, value: int):
        """Set the data size."""
        ...

    @property
    def data(self) -> bytes:
        """Get the request data."""
        ...

    @data.setter
    def data(self, value: bytes):
        """Set the request data."""
        ...

    def to_string(self) -> bytes:
        """Convert the request to a string."""
        ...

    @staticmethod
    def from_string(data: bytes) -> Request:
        """Create a request from a string."""
        ...