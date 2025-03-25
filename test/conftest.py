from __future__ import annotations

import pytest

from dotenv import dotenv_values

from pycofhe.network import make_cpucryptosystem_client_node


@pytest.fixture
def client_node():
    """Fixture for a CPUCryptoSystemClientNode."""
    env_vars = dotenv_values(".env")
    client_node_ip = env_vars["CLIENT_NODE_IP"]
    if not client_node_ip:
        raise ValueError("CLIENT_NODE_IP environment variable is not set.")
    client_node_port = env_vars["CLIENT_NODE_PORT"]
    if not client_node_port:
        raise ValueError("CLIENT_NODE_PORT environment variable is not set.")
    setup_node_ip = env_vars["SETUP_NODE_IP"]
    if not setup_node_ip:
        raise ValueError("SETUP_NODE_IP environment variable is not set.")
    setup_node_port = env_vars["SETUP_NODE_PORT"]
    if not setup_node_port:
        raise ValueError("SETUP_NODE_PORT environment variable is not set.")
    cert_path = env_vars["CERT_PATH"]
    if not cert_path:
        raise ValueError("CERT_PATH environment variable is not set.")
    return make_cpucryptosystem_client_node(
        client_node_ip,
        client_node_port,
        setup_node_ip,
        setup_node_port,
        cert_path,
    )