#include <string>

#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

#include "cofhe.hpp"

using namespace CoFHE;
namespace py = pybind11;

template <typename CryptoSystem>
inline typename CryptoSystem::CipherText
add(ClientNode<CryptoSystem>& client_node,
    const typename CryptoSystem::CipherText& ct1,
    const typename CryptoSystem::CipherText& ct2) {
    return client_node.crypto_system().add_ciphertexts(
        client_node.network_public_key(), ct1, ct2);
}

template <typename CryptoSystem>
inline typename CryptoSystem::CipherText
sub(ClientNode<CryptoSystem>& client_node,
    const typename CryptoSystem::CipherText& ct1,
    const typename CryptoSystem::CipherText& ct2) {
    return client_node.crypto_system().add_ciphertexts(
        client_node.network_public_key(), ct1,
        client_node.crypto_system().negate_ciphertext(
            client_node.network_public_key(), ct2));
}

template <typename CryptoSystem>
float gteq_and_decrypt(ClientNode<CryptoSystem>& client_node,
                       const typename CryptoSystem::CipherText& ct1,
                       const typename CryptoSystem::CipherText& ct2) {
    std::string serialized_ct1 =
        client_node.crypto_system().serialize_ciphertext(ct1);
    std::string serialized_ct2 =
        client_node.crypto_system().serialize_ciphertext(ct2);

    ComputeRequest::ComputeOperationOperand operand1(
        ComputeRequest::DataType::SINGLE,
        ComputeRequest::DataEncrytionType::CIPHERTEXT, serialized_ct1);

    ComputeRequest::ComputeOperationOperand operand2(
        ComputeRequest::DataType::SINGLE,
        ComputeRequest::DataEncrytionType::CIPHERTEXT, serialized_ct2);

    ComputeRequest::ComputeOperationInstance operation(
        ComputeRequest::ComputeOperationType::BINARY,
        ComputeRequest::ComputeOperation::GTEQ, {operand1, operand2});

    ComputeRequest req(operation);
    ComputeResponse* res = nullptr;
    client_node.compute(req, &res);

    if (!res || res->status() != ComputeResponse::Status::OK) {
        std::cerr << "Error: " << static_cast<int>(res->status()) << std::endl;
        if (res) {
            std::cerr << "Error message: " << res->data() << std::endl;
        }
        delete res;
        std::exit(1);
    }

    ComputeRequest::ComputeOperationOperand decrypt_operand(
        ComputeRequest::DataType::SINGLE,
        ComputeRequest::DataEncrytionType::CIPHERTEXT, res->data());
    delete res;

    ComputeRequest::ComputeOperationInstance decrypt_operation(
        ComputeRequest::ComputeOperationType::UNARY,
        ComputeRequest::ComputeOperation::DECRYPT, {decrypt_operand});

    ComputeRequest decrypt_req(decrypt_operation);
    ComputeResponse* decrypt_res = nullptr;

    client_node.compute(decrypt_req, &decrypt_res);

    if (!decrypt_res || decrypt_res->status() != ComputeResponse::Status::OK) {
        std::cerr << "Error: " << static_cast<int>(decrypt_res->status())
                  << std::endl;
        if (decrypt_res) {
            std::cerr << "Error message: " << decrypt_res->data() << std::endl;
        }
        delete decrypt_res;
        std::exit(1);
    }

    auto decrypted_result =
        client_node.crypto_system().get_float_from_plaintext(
            client_node.crypto_system().deserialize_plaintext(
                decrypt_res->data()));
    delete decrypt_res;
    return decrypted_result;
}

template <typename CryptoSystem>
std::pair<bool, std::pair<typename CryptoSystem::CipherText,
                          typename CryptoSystem::CipherText>>
native_transfer_func(ClientNode<CryptoSystem>& client_node,
                     const typename CryptoSystem::CipherText& sender_balance,
                     const typename CryptoSystem::CipherText& receiver_balance,
                     const typename CryptoSystem::CipherText& amount) {
    if (gteq_and_decrypt(client_node, sender_balance, amount) > 0) {
        return std::make_pair(
            true, std::make_pair(sub(client_node, sender_balance, amount),
                                 add(client_node, receiver_balance, amount)));
    }
    return std::make_pair(false,
                          std::make_pair(sender_balance, receiver_balance));
}

template <typename CryptoSystem>
void init_native_transfer_func_bindings(py::module_& m) {

    m.def("native_transfer_func", native_transfer_func<CryptoSystem>,
          py::arg("client_node"), py::arg("sender_balance"),
          py::arg("receiver_balance"), py::arg("amount"),
          R"pbdoc(
Transfer function for native transfer.

Args:
   client_node (ClientNode): The client node to use.
   sender_balance (Ciphertext): The balance of the sender.
   receiver_balance (Ciphertext): The balance of the receiver.
   amount (Ciphertext): The amount to transfer.

Returns:
   Tuple[bool, Tuple[Ciphertext, Ciphertext]]: A tuple containing a
   boolean indicating whether the transfer is valid and a tuple
   containing the new sender and receiver balances.
)pbdoc");
}

void init_cpu_cryptosystem_native_transfer_func_bindings(py::module_& m) {
    init_native_transfer_func_bindings<CPUCryptoSystem>(m);
}