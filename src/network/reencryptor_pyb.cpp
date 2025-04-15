#include <string>

#include <pybind11/functional.h>
#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

#include "cofhe.hpp"

using namespace CoFHE;
namespace py = pybind11;

template <typename PKCEncryptor, typename CryptoSystem>
void init_reencryptor_bindings(py::module_& m,
                               const std::string& encryptor_identifier,
                               const std::string& cryptosystem_identifier) {
    const std::string reencryptor_class_name =
        encryptor_identifier + cryptosystem_identifier + "Reencryptor";
    const std::string reencryptor_key_pair_class_name =
        encryptor_identifier + "ReencryptionKeyPair";

    py::class_<PKCEncryptor>(m, encryptor_identifier.c_str());

    using ReencryptionKeyPair =
        PartialDecryptionResultReencryption<PKCEncryptor,
                                            CryptoSystem>::ReencryptionKeyPair;
    py::class_<ReencryptionKeyPair>(m, reencryptor_key_pair_class_name.c_str());

    py::class_<PartialDecryptionResultReencryption<PKCEncryptor, CryptoSystem>>(
        m, reencryptor_class_name.c_str())
        .def(
            "decrypt",
            [](PartialDecryptionResultReencryption<PKCEncryptor, CryptoSystem>&
                   reencryptor,
               py::bytes reencryted_partial_decryption_result,
               CryptoSystem::CipherText& ct, py::bytes serialized_private_key) {
                std::string private_key_str = serialized_private_key;
                auto private_key =
                    reencryptor.deserialize_reencryption_private_key(
                        private_key_str);
                std::string data_str = reencryted_partial_decryption_result;
                auto reencrypted_pdrs = ClientNode<CPUCryptoSystem>::
                    ReencryptorType::split_reencrypted_messages(data_str);
                return reencryptor.decrypt(reencrypted_pdrs, ct, private_key);
            },
            py::arg("reencryted_partial_decryption_result"), py::arg("ct"),
            py::arg("private_key"),
            R"pbdoc(
                Decrypt a reencrypted partial decryption results using the private key.

                Args:
                    reencryted_partial_decryption_result (bytes): The serialized reencrypted partial decryption result.
                    ct (CipherText): The ciphertext.
                    private_key (ReencryptionKeyPair): The private key.

                Returns:
                    PlainText: The decrypted plaintext.
            )pbdoc")
        .def(
            "decrypt_tensor",
            [](PartialDecryptionResultReencryption<PKCEncryptor, CryptoSystem>&
                   reencryptor,
               py::bytes reencryted_partial_decryption_result,
               Tensor<CPUCryptoSystem::CipherText*>& ct,
               py::bytes serialized_private_key) {
                std::string private_key_str = serialized_private_key;
                auto private_key =
                    reencryptor.deserialize_reencryption_private_key(
                        private_key_str);
                std::string data_str = reencryted_partial_decryption_result;
                auto reencrypted_pdrs = ClientNode<CPUCryptoSystem>::
                    ReencryptorType::split_reencrypted_messages(data_str);
                return reencryptor.decrypt_tensor(reencrypted_pdrs, ct,
                                                  private_key);
            },
            py::arg("reencryted_partial_decryption_result"), py::arg("ct"),
            py::arg("private_key"),
            R"pbdoc(
                Decrypt a tensor of reencrypted partial decryption results using the private key.

                Args:
                    reencryted_partial_decryption_result (bytes): The serialized reencrypted partial decryption result.
                    ct (Tensor[CipherText]): The tensor of ciphertexts.
                    private_key (ReencryptionKeyPair): The private key.

                Returns:
                    Tensor[PlainText]: The decrypted plaintext tensor.
            )pbdoc")
        .def(
            "generate_serialized_key_pair",
            [](PartialDecryptionResultReencryption<PKCEncryptor, CryptoSystem>&
                   reencryptor) {
                auto key_pair = reencryptor.generate_reencryption_key_pair();
                return std::pair<py::bytes, py::bytes>(
                    py::bytes(reencryptor.serialize_reencryption_private_key(
                        key_pair)),
                    py::bytes(reencryptor.serialize_reencryption_public_key(
                        key_pair)));
            },
            R"pbdoc(
                    Generate a reencryption key pair and serialize it.
    
                    Returns:
                        Tuple[bytes, bytes]: The serialized private and public keys.
                )pbdoc");
}



void init_rsa_reencryptor_and_cpu_cryptosystem_bindings(py::module_& m) {
    init_reencryptor_bindings<RSAPKCEncryptor, CPUCryptoSystem>(
        m, "RSAPKCEncryptor", "CPUCryptoSystem");
}