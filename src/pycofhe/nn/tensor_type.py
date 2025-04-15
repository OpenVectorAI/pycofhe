from __future__ import annotations

import enum


class TensorType(enum.Enum):
    """Enum for tensor types."""

    Float = 0
    PlainText = 1
    CipherText = 2
