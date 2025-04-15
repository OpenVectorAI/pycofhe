#include <string>

#include <pybind11/pybind11.h>

#include "cofhe.hpp"

using namespace CoFHE;
namespace py = pybind11;

void init_compute_request_response_bindings(py::module_& m);
void init_network_details_bindings(py::module_& m);
// template <typename CryptoSystem>
// void init_client_node_bindings(py::module_& m,
//                                const std::string& cryptosystem_identifier,
//                                const std::string& factory_func_identifier);
// template <typename CryptoSystem>
// void init_binary_cryptosystem_bindings(py::module_& m);
// template <typename PKCEncryptor, typename CryptoSystem>
// void init_reencryptor_bindings(py::module_& m,
//                                const std::string& cryptosystem_identifier,
//                                const std::string& encryptor_identifier);
// template <typename CryptoSystem>
// void init_native_transfer_func_bindings(py::module_& m);
void init_cpu_cryptosystem_client_node_bindings(
    py::module_& m);
void init_cpu_binary_cryptosystem_bindings(py::module_& m);
void init_rsa_reencryptor_and_cpu_cryptosystem_bindings(
    py::module_& m);
void init_cpu_cryptosystem_native_transfer_func_bindings(
    py::module_& m);

PYBIND11_MODULE(network_core, m) {
    m.doc() = "Python binding for CoFHE networking";

    init_compute_request_response_bindings(m);
    init_network_details_bindings(m);
    init_rsa_reencryptor_and_cpu_cryptosystem_bindings(m);
    init_cpu_cryptosystem_client_node_bindings(m);
    init_cpu_binary_cryptosystem_bindings(m);
    init_cpu_cryptosystem_native_transfer_func_bindings(m);
    // init_reencryptor_bindings<RSAPKCEncryptor, CPUCryptoSystem>(
    //     m, "RSAPKCEncryptor", "CPUCryptoSystem");
    // init_client_node_bindings<CPUCryptoSystem>(m, "CPUCryptoSystem",
    //                                            "cpu_cryptosystem");
    // init_binary_cryptosystem_bindings<CPUCryptoSystem>(m);
    // init_native_transfer_func_bindings<CPUCryptoSystem>(m);
}