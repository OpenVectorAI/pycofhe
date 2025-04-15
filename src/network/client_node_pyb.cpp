#include <string>

#include <pybind11/functional.h>
#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

#include "cofhe.hpp"

using namespace CoFHE;
namespace py = pybind11;

template <typename CryptoSystem>
ClientNode<CryptoSystem>
make_client_node(const std::string& client_ip, const std::string& client_port,
                 const std::string& setup_ip, const std::string& setup_port,
                 const std::string& cert_file = "./server.pem") {
    auto setup_node_details = NodeDetails(setup_ip, setup_port);
    return make_client_node<CryptoSystem>(setup_node_details, cert_file);
}

template <typename CryptoSystem>
ClientNode<CryptoSystem>
make_client_node(NetworkDetails& network_details,
                 const std::string& cert_file = "./server.pem") {
    return ClientNode<CryptoSystem>(network_details, cert_file);
}

template <typename CryptoSystem>
void init_client_node_bindings(py::module_& m,
                               const std::string& cryptosystem_identifier,
                               const std::string& factory_func_identifier) {
    const std::string client_class_name =
        cryptosystem_identifier + "ClientNode";
    const std::string factory_func_name =
        "make_" + factory_func_identifier + "_client_node";
    py::class_<ClientNode<CryptoSystem>>(m, client_class_name.c_str())
        .def(
            "compute",
            [](ClientNode<CryptoSystem>& node, const ComputeRequest& request) {
                ComputeResponse* response = nullptr;
                try {
                    node.compute(request, &response);
                } catch (const std::exception& e) {
                    std::cerr << e.what() << std::endl;
                }
                if (response == nullptr) {
                    throw std::runtime_error("Failed to compute the request.");
                }
                return *response;
            },
            py::arg("request"),
            R"pbdoc(
                Compute the given request.

                Args:
                    request (ComputeRequest): The request to compute.

                Returns:
                    ComputeResponse: The response to the request.
            )pbdoc")
        .def_property_readonly(
            "cryptosystem",
            py::overload_cast<>(&ClientNode<CryptoSystem>::crypto_system,
                                py::const_),

            R"pbdoc(
            Get the cryptosystem of the client node.

            Returns:
                CryptoSystem: The cryptosystem of the client node.
        )pbdoc")
        .def_property_readonly(
            "network_encryption_key",
            py::overload_cast<>(&ClientNode<CryptoSystem>::network_public_key,
                                py::const_),
            R"pbdoc(
            Get the network encryption key of the client node.

            Returns:
                PublicKey: The network encryption key of the client node.
        )pbdoc")
        .def_property_readonly(
            "reencryptor",
            py::overload_cast<>(&ClientNode<CryptoSystem>::reencryptor,
                                py::const_),
            R"pbdoc(
            Get the reencryptor of the client node.
            Returns:
                Reencryptor: The reencryptor of the client node.
        )pbdoc")
        .def_property_readonly(
            "network_details",
            py::overload_cast<>(&ClientNode<CryptoSystem>::network_details,
                                py::const_),
            R"pbdoc(
            Get the network details of the client node.

            Returns:
                NetworkDetails: The network details of the client node.
        )pbdoc");

    m.def(
        factory_func_name.c_str(),
        py::overload_cast<const std::string&, const std::string&,
                          const std::string&, const std::string&,
                          const std::string&>(&make_client_node<CryptoSystem>),
        py::arg("client_ip"), py::arg("client_port"), py::arg("setup_ip"),
        py::arg("setup_port"), py::arg("cert_file") = "./server.pem",
        R"pbdoc(
        Create a client node for the particular cryptosystem.
        
        Args:
            client_ip (str): The IP address of the client node.
            client_port (str): The port of the client node.
            setup_ip (str): The IP address of the setup node.
            setup_port (str): The port of the setup node.
            cert_file (str): The certificate file for the client node. Default is "./server.pem".

        Returns:
            ClientNode<CryptoSystem>: A client node for the particular cryptosystem.
    )pbdoc");

    m.def(factory_func_name.c_str(),
          py::overload_cast<NetworkDetails&, const std::string&>(
              &make_client_node<CryptoSystem>),
          py::arg("network_details"), py::arg("cert_file") = "./server.pem",
          R"pbdoc(
        Create a client node for the particular cryptosystem.

        Args:
            network_details (NetworkDetails): The network details of the client node.
            cert_file (str): The certificate file for the client node. Default is "./server.pem".

        Returns:
            ClientNode<CryptoSystem>: A client node for the particular cryptosystem.
    )pbdoc");
}

void init_cpu_cryptosystem_client_node_bindings(py::module_& m) {
    init_client_node_bindings<CPUCryptoSystem>(m, "CPUCryptoSystem",
                                               "cpu_cryptosystem");
}