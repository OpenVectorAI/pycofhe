#include <string>

#include <pybind11/functional.h>
#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

#include "cofhe.hpp"

using namespace CoFHE;
namespace py = pybind11;

ClientNode<CPUCryptoSystem> make_cpucryptosystem_client_node(
    const std::string& client_ip, const std::string& client_port,
    const std::string& setup_ip, const std::string& setup_port,
    const std::string& cert_file = "./server.pem") {
    auto setup_node_details = NodeDetails(setup_ip, setup_port);
    return make_client_node<CPUCryptoSystem>(setup_node_details, cert_file);
}

void init_client_node_bindings(py::module_& m) {

    using ClientNode = ClientNode<CPUCryptoSystem>;

    py::class_<ClientNode>(m, "CPUCryptoSystemClientNode")
        .def(
            "compute",
            [](ClientNode& node, const ComputeRequest& request) {
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
            py::overload_cast<>(&ClientNode::crypto_system, py::const_),
            R"pbdoc(
            Get the cryptosystem of the client node.

            Returns:
                CPUCryptoSystem: The cryptosystem of the client node.
        )pbdoc")
        .def_property_readonly(
            "network_encryption_key",
            py::overload_cast<>(&ClientNode::network_public_key, py::const_),
            R"pbdoc(
            Get the network encryption key of the client node.

            Returns:
                PublicKey: The network encryption key of the client node.
        )pbdoc");

    m.def("make_cpucryptosystem_client_node", make_cpucryptosystem_client_node,
          py::arg("client_ip"), py::arg("client_port"), py::arg("setup_ip"),
          py::arg("setup_port"), py::arg("cert_file") = "./server.pem",
          R"pbdoc(
        Create a client node for the CPU cryptosystem.
        
        Args:
            client_ip (str): The IP address of the client node.
            client_port (str): The port of the client node.
            setup_ip (str): The IP address of the setup node.
            setup_port (str): The port of the setup node.
            cert_file (str): The certificate file for the client node. Default is "./server.pem".

        Returns:
            ClientNode: A client node for the CPU cryptosystem.
    )pbdoc");
}