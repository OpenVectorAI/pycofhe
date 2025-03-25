#include <string>

#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

#include "cofhe.hpp"

namespace py = pybind11;

using namespace CoFHE;
using namespace CoFHE::binary_scheme;

void init_binary_cpu_cryptosystem_bindings(py::module_& m) {

    m.def("encrypt_bit", encrypt_bit, py::arg("cs"), py::arg("pk"),
          py::arg("plaintext"),
          R"pbdoc(
                Encrypt the given plaintext using binary encoding scheme.

                Args:
                    cs (CPUCryptoSystem): The cryptosystem to use.
                    pk (PublicKey): The public key to use.
                    plaintext (int): The plaintext to encrypt.

                Returns:
                    CipherText: The encrypted ciphertext, in binary encoding.
            )pbdoc");

    m.def("decrypt_bit", decrypt_bit, py::arg("client_node"), py::arg("ct"),
          R"pbdoc(
                Decrypt the given ciphertext using binary encoding scheme.

                Args:
                    client_node (CPUCryptoSystemClientNode): The client node to use.
                    ct (CipherText): The ciphertext to decrypt.

                Returns:
                    int: The decrypted bit.
            )pbdoc");

    m.def("homomorphic_not",
            py::overload_cast<ClientNode<CPUCryptoSystem>&,
                                const CPUCryptoSystem::CipherText&>(homomorphic_not),
            py::arg("client_node"), py::arg("ct"),
            R"pbdoc(
                    Perform homomorphic NOT operation on the given binary encoded
                    ciphertext.
    
                    Args:
                        client_node (CPUCryptoSystemClientNode): The client node
                        to use. ct (Ciphertext): The ciphertext to negate.
    
                    Returns:
                        Ciphertext: The result of the homomorphic NOT operation.
                )pbdoc");

                
                m.def("homorphic_and",
                    py::overload_cast<ClientNode<CPUCryptoSystem>&,
                    const CPUCryptoSystem::CipherText&,
                    const CPUCryptoSystem::CipherText&>(homomorphic_and),
                    py::arg("client_node"), py::arg("ct1"), py::arg("ct2"),
                    R"pbdoc(
                        Perform homomorphic AND operation on the given ciphertexts.
                        
                        Args:
                        client_node (CPUCryptoSystemClientNode): The client node to use.
                        ct1 (Ciphertext): The first ciphertext.
                        ct2 (Ciphertext): The second ciphertext.
                        
                        Returns:
                        Ciphertext: The result of the homomorphic AND operation.
                        )pbdoc");
                        
    m.def("homomorphic_or", py::overload_cast<ClientNode<CPUCryptoSystem>&,
        const CPUCryptoSystem::CipherText&,
        const CPUCryptoSystem::CipherText&>(homomorphic_or),
        py::arg("client_node"), py::arg("ct1"), py::arg("ct2"),
        R"pbdoc(
            Perform homomorphic OR operation on the given binary encoded
            ciphertexts.
            
            Args:
            client_node (CPUCryptoSystemClientNode): The client node
            to use. ct1 (Ciphertext): The first ciphertext. ct2
            (Ciphertext): The second ciphertext.
            
            Returns:
            Ciphertext: The result of the homomorphic OR operation.
            )pbdoc");

    m.def("homomorphic_xor", py::overload_cast<ClientNode<CPUCryptoSystem>&,
        const CPUCryptoSystem::CipherText&,
        const CPUCryptoSystem::CipherText&>(homomorphic_xor),
        py::arg("client_node"), py::arg("ct1"), py::arg("ct2"),
        R"pbdoc(
            Perform homomorphic XOR operation on the given binary encoded
            ciphertexts.
            
            Args:
            client_node (CPUCryptoSystemClientNode): The client node
            to use. ct1 (Ciphertext): The first ciphertext. ct2
            (Ciphertext): The second ciphertext.
            
            Returns:
            Ciphertext: The result of the homomorphic XOR operation.
            )pbdoc");
            
    m.def(
        "homomorphic_nand",
        [](ClientNode<CPUCryptoSystem>& client_node,
           const CPUCryptoSystem::CipherText& ct1,
           const CPUCryptoSystem::CipherText& ct2) {
            return homomorphic_not(client_node,
                                   homomorphic_and(client_node, ct1, ct2));
        },
        py::arg("client_node"), py::arg("ct1"), py::arg("ct2"),
        R"pbdoc(
                Perform homomorphic NAND operation on the given binary encoded
                ciphertexts.

                Args:
                    client_node (CPUCryptoSystemClientNode): The client node
                    to use. ct1 (Ciphertext): The first ciphertext. ct2
                    (Ciphertext): The second ciphertext.

                Returns:
                    Ciphertext: The result of the homomorphic NAND operation.
            )pbdoc");

    m.def("encrypt_bitwise", encrypt_bitwise, py::arg("cs"), py::arg("pk"),
          py::arg("plaintext"),
          R"pbdoc(
                Encrypt the given plaintext using binary encoding scheme.

                Args:
                    cs (CPUCryptoSystem): The cryptosystem to use.
                    pk (PublicKey): The public key to use.
                    plaintext (int): The plaintext to encrypt.

                Returns:
                    List[Ciphertext]: The encrypted ciphertext, in binary encoding.
            )pbdoc");

    m.def("decrypt_bitwise", decrypt_bitwise, py::arg("client_node"),
          py::arg("cts"),
          R"pbdoc(
                Decrypt the given ciphertext using binary encoding scheme.

                Args:
                    client_node (CPUCryptoSystemClientNode): The client node to use.
                    cts (List[Ciphertext]): The ciphertext to decrypt.

                Returns:
                    int: The decrypted plaintext.
            )pbdoc");

    m.def("homomorphic_and",
          py::overload_cast<ClientNode<CPUCryptoSystem>&,
                            const Vector<CPUCryptoSystem::CipherText>&,
                            const Vector<CPUCryptoSystem::CipherText>&>(
              homomorphic_and),
          py::arg("client_node"), py::arg("ct1"), py::arg("ct2"),
          R"pbdoc(
                Perform homomorphic AND operation on the given ciphertexts.

                Args:
                    client_node (CPUCryptoSystemClientNode): The client node to use.
                    ct1 (List[Ciphertext]): The first ciphertext.
                    ct2 (List[Ciphertext]): The second ciphertext.

                Returns:
                    List[Ciphertext]: The result of the homomorphic AND operation.
            )pbdoc");

    m.def("homomorphic_or",
          py::overload_cast<ClientNode<CPUCryptoSystem>&,
                            const Vector<CPUCryptoSystem::CipherText>&,
                            const Vector<CPUCryptoSystem::CipherText>&>(
              homomorphic_or),
          py::arg("client_node"), py::arg("ct1"), py::arg("ct2"),
          R"pbdoc(
                Perform homomorphic OR operation on the given binary encoded
                ciphertexts.

                Args:
                    client_node (CPUCryptoSystemClientNode): The client node
                    to use. ct1 (List[Ciphertext]): The first ciphertext. ct2
                    (List[Ciphertext]): The second ciphertext.

                Returns:
                    List[Ciphertext]: The result of the homomorphic OR
                    operation.
            )pbdoc");

    m.def("homomorphic_not",
          py::overload_cast<ClientNode<CPUCryptoSystem>&,
                            const Vector<CPUCryptoSystem::CipherText>&>(
              homomorphic_not),
          py::arg("client_node"), py::arg("cts"),
          R"pbdoc(
                Perform homomorphic NOT operation on the given binary encoded
                ciphertext.

                Args:
                    client_node (CPUCryptoSystemClientNode): The client node
                    to use. cts (List[Ciphertext]): The ciphertext to negate.

                Returns:
                    List[Ciphertext]: The result of the homomorphic NOT
                    operation.

            )pbdoc");

    m.def("homomorphic_xor",
          py::overload_cast<ClientNode<CPUCryptoSystem>&,
                            const Vector<CPUCryptoSystem::CipherText>&,
                            const Vector<CPUCryptoSystem::CipherText>&>(
              homomorphic_xor),
          py::arg("client_node"), py::arg("ct1"), py::arg("ct2"),
          R"pbdoc(
                Perform homomorphic XOR operation on the given binary encoded
                ciphertexts.

                Args:
                    client_node (CPUCryptoSystemClientNode): The client node
                    to use. ct1 (List[Ciphertext]): The first ciphertext. ct2
                    (List[Ciphertext]): The second ciphertext.

                Returns:
                    List[Ciphertext]: The result of the homomorphic XOR
                    operation.
            )pbdoc");

    m.def("homomorphic_add", homomorphic_add, py::arg("client_node"),
          py::arg("ct1"), py::arg("ct2"),
          R"pbdoc(
                Perform homomorphic NAND operation on the given binary
                encoded ciphertexts.

                Args:
                    client_node (CPUCryptoSystemClientNode): The client node
                    to use. ct1 (List[Ciphertext]): The first ciphertext. ct2
                    (List[Ciphertext]): The second ciphertext.

                Returns:
                    List[Ciphertext]: The result of the homomorphic NAND
                    operation.
            )pbdoc");

    m.def("homomorphic_sub", homomorphic_sub, py::arg("client_node"),
          py::arg("ct1"), py::arg("ct2"),
          R"pbdoc(
                    Perform homomorphic sub operation on the given binary
                    encoded ciphertexts.

                    Args:
                        client_node (CPUCryptoSystemClientNode): The client
                        node to use. ct1 (List[Ciphertext]): The first
                        ciphertext. ct2 (List[Ciphertext]): The second
                        ciphertext.

                    Returns:
                        List[Ciphertext]: The result of the homomorphic NOR
                        operation.
                )pbdoc");

    m.def("homomorphic_lt", homomorphic_lt, py::arg("client_node"),
          py::arg("ct1"), py::arg("ct2"),
          R"pbdoc(
                    Perform homomorphic less than operation on the given
                    binary encoded ciphertexts.

                    Args:
                        client_node (CPUCryptoSystemClientNode): The client
                        node to use. ct1 (List[Ciphertext]): The first
                        ciphertext. ct2 (List[Ciphertext]): The second
                        ciphertext.

                    Returns:
                        CipherText The result of the homomorphic less
                        than operation.
                )pbdoc");

    m.def("homomorphic_eq", homomorphic_eq, py::arg("client_node"),
          py::arg("ct1"), py::arg("ct2"),
          R"pbdoc(
                    Perform homomorphic equal operation on the given binary
                    encoded ciphertexts.

                    Args:
                        client_node (CPUCryptoSystemClientNode): The client
                        node to use. ct1 (List[Ciphertext]): The first
                        ciphertext. ct2 (List[Ciphertext]): The second
                        ciphertext.

                    Returns:
                        Ciphertext: The result of the homomorphic equal
                        operation.
                )pbdoc");

    m.def("homomorphic_gt", homomorphic_gt, py::arg("client_node"),
          py::arg("ct1"), py::arg("ct2"),
          R"pbdoc(
                    Perform homomorphic greater than operation on the given
                    binary encoded ciphertexts.

                    Args:
                        client_node (CPUCryptoSystemClientNode): The client
                        node to use. ct1 (List[Ciphertext]): The first
                        ciphertext. ct2 (List[Ciphertext]): The second
                        ciphertext.

                    Returns:
                        Ciphertext: The result of the homomorphic
                        greater than operation.
                )pbdoc");

    m.def("serialize_bit", serialize_bit, py::arg("cs"), py::arg("ct"),
          R"pbdoc(
                Serialize the given binary encoded ciphertext.

                Args:
                    cs (CPUCryptoSystem): The cryptosystem to use.
                    ct (Ciphertext): The ciphertext to serialize.

                Returns:
                    str: The serialized ciphertext.
            )pbdoc");

    m.def("deserialize_bit", deserialize_bit, py::arg("cs"), py::arg("s"),
          R"pbdoc(
                    Deserialize the given binary encoded ciphertext.
    
                    Args:
                        cs (CPUCryptoSystem): The cryptosystem to use.
                        s (str): The serialized ciphertext.
    
                    Returns:
                        Ciphertext: The deserialized ciphertext.
                )pbdoc");

    m.def("serialize_bitwise", serialize_bitwise, py::arg("cs"), py::arg("cts"),
          R"pbdoc(
                    Serialize the given binary encoded ciphertexts.
    
                    Args:
                        cs (CPUCryptoSystem): The cryptosystem to use.
                        cts (List[Ciphertext]): The ciphertexts to serialize.
    
                    Returns:
                        str: The serialized ciphertext.
                )pbdoc");

    m.def("deserialize_bitwise", deserialize_bitwise, py::arg("cs"),
          py::arg("s"),
          R"pbdoc(
                    Deserialize the given binary encoded ciphertext.
    
                    Args:
                        cs (CPUCryptoSystem): The cryptosystem to use.
                        s (str): The serialized ciphertext.
    
                    Returns:
                        List[Ciphertext]: The deserialized ciphertext.
                )pbdoc");
}