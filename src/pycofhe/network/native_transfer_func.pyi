"""Typing stubs for the binary scheme core functions."""

from __future__ import annotations

from typing import Tuple

from pycofhe.cryptosystems.cryptosystem import (
    CipherText,
    PartialDecryptionResult,
    PlainText,
    PublicKey,
    SecretKey,
    SecretKeyShare,
)
from pycofhe.network.network_core import ClientNode
from pycofhe.network.reencryptor import PKCEncryptor

# pylint: disable=unused-argument,unnecessary-ellipsis

def native_transfer_func(
    cs: ClientNode[
        SecretKey,
        SecretKeyShare,
        PublicKey,
        PlainText,
        CipherText,
        PartialDecryptionResult,
        PKCEncryptor,
    ],
    sender_balance: CipherText,
    receiver_balance: CipherText,
    amount: CipherText,
) -> Tuple[bool, Tuple[CipherText, CipherText]]:
    """Perform a native transfer operation.

    Args:
        cs (ClientNode): The cryptosystem client node.
        sender_balance (CipherText): The balance of the sender.
        receiver_balance (CipherText): The balance of the receiver.
        amount (CipherText): The amount to transfer.

    Returns:
        Tuple[bool,Tuple[CipherText,CipherText]]: A tuple containing a boolean indicating success and a tuple containing the new sender and receiver balances.
    """
    ...
