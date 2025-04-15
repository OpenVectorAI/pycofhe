"""Test the binary CPU cryptosystem related utils functions."""

from __future__ import annotations
import random
import pytest


from pycofhe.network import native_transfer_func
from pycofhe.network import perform_decryption


def test_native_transfer_func(client_node):
    """Test the native_transfer_func function."""
    sender_balance = random.randint(0, 100)
    receiver_balance = random.randint(0, 100)
    amount = random.randint(0, 100)
    encrypted_sender_balance = client_node.cryptosystem.encrypt(
        client_node.network_encryption_key,
        client_node.cryptosystem.make_plaintext(sender_balance),
    )
    encrypted_receiver_balance = client_node.cryptosystem.encrypt(
        client_node.network_encryption_key,
        client_node.cryptosystem.make_plaintext(receiver_balance),
    )
    encrypted_amount = client_node.cryptosystem.encrypt(
        client_node.network_encryption_key,
        client_node.cryptosystem.make_plaintext(amount),
    )

    success, new_enc_balances = native_transfer_func(
        client_node,
        encrypted_sender_balance,
        encrypted_receiver_balance,
        encrypted_amount,
    )

    new_balances = [0, 0]
    new_balances[0] = client_node.cryptosystem.get_float_from_plaintext(
        perform_decryption(client_node, new_enc_balances[0])
    )
    new_balances[1] = client_node.cryptosystem.get_float_from_plaintext(
        perform_decryption(client_node, new_enc_balances[1])
    )

    if success:
        assert (
            sender_balance >= amount
        ), "Sender balance should be greater than or equal to the amount."
        assert (
            new_balances[0] == sender_balance - amount
        ), "Sender balance should be decremented by the amount."
        assert (
            new_balances[1] == receiver_balance + amount
        ), "Receiver balance should be incremented by the amount."
    else:
        assert (
            sender_balance < amount
        ), "Sender balance should be less than the amount."
        assert (
            new_balances[0] == sender_balance
        ), "Sender balance should remain unchanged."
        assert (
            new_balances[1] == receiver_balance
        ), "Receiver balance should remain unchanged."
