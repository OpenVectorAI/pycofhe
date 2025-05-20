# PyCOFHE

**PyCOFHE** is a Python library that provides bindings to the C++ library **COFHE** (Collaborative Fully Homomorphic Encryption). This library enables the use of CoFHE in Python, making it easier to integrate secure computation into machine learning and other applications.

In addition to the bindings, PyCOFHE extends the functionality by including common machine learning utilities, starting with support for a **linear layer** in neural networks.

## Features

- **COFHE Bindings**: Access the powerful collaborative fully homomorphic encryption functionalities of COFHE directly in Python via **PyBind11**.
- **Machine Learning Integration**: Includes support for a basic neural network linear layer with plans for more machine learning utilities in future versions.

## Getting Started

### Prerequisites

- Python 3.8+
- C++20
- CMake
- Git
- PyBind11

### Build Instructions

1. Clone the repository:

   ```bash
   git clone https://github.com/openvectorai/pycofhe.git
   cd pycofhe
   ```

2. Initialize submodules recursively:

   ```bash
   git submodule update --init --recursive
   ```

3. Synchronize and build using `uv`:

   ```bash
   uv sync
   uv build
   ```

### Running Tests

Run the test suite using the following command:

```bash
uv run pytest
```

## Usage

Here’s an example usage from the test cases:

```python
cert_path = "xx/server.pem" # Path to the compute node certificate
node = make_cpucryptosystem_client_node(
    "127.0.0.1", "50051", "127.0.0.1", "4455", cert_path
)
cs = node.cryptosystem
pk = node.network_encryption_key

c1 = cs.encrypt_tensor(pk, cs.make_plaintext_tensor([4], [1, 2**5, 3, 4]))
p1 = cs.make_plaintext_tensor([4], [5, 6, 7, 8])
c = cs.scal_ciphertext_tensors(pk, p1, c1)
c2 = cs.encrypt_tensor(pk, p1)

op1 = ComputeOperationOperand(
    DataType.TENSOR,
    DataEncryptionType.CIPHERTEXT,
    cs.serialize_ciphertext_tensor(c),
)
op2 = ComputeOperationOperand(
    DataType.TENSOR,
    DataEncryptionType.CIPHERTEXT,
    cs.serialize_ciphertext_tensor(c2),
)

op_instance = ComputeOperationInstance(
    ComputeOperationType.BINARY, ComputeOperation.MULTIPLY, [op1, op2]
)
req = ComputeRequest(op_instance)
res = node.compute(req)

dop = ComputeOperationOperand(
    DataType.TENSOR, DataEncryptionType.CIPHERTEXT, res.data_bytes
)
dop_instance = ComputeOperationInstance(
    ComputeOperationType.UNARY, ComputeOperation.DECRYPT, [dop]
)
req = ComputeRequest(dop_instance)
res = node.compute(req)

dres = cs.deserialize_plaintext_tensor(res.data_bytes)
float_res = cs.get_float_from_plaintext_tensor(dres)

assert float_res == [25.0, 1152.0, 147.0, 256.0]
```

## Contributing

We welcome contributions! If you’d like to contribute:

1. Fork the repository.
2. Create a feature branch: `git checkout -b feature-name`.
3. Commit your changes: `git commit -m 'Add new feature'`.
4. Push to the branch: `git push origin feature-name`.
5. Open a pull request.

## Roadmap

- Add more machine learning utilities.
- Provide extensive documentation and examples.

## License

This project is licensed under the [BSD 3-Clause License](LICENSE).


## Contact

For further information or assistance:

- **Email**: [support@openvector.ai](mailto:support@openvector.ai)