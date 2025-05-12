#include <string>
#include <vector>

#include <pybind11/functional.h>
#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

#include "cofhe.hpp"

using namespace CoFHE;
namespace py = pybind11;

void init_network_details_bindings(py::module_& m) {
    py::enum_<NodeType>(m, "NodeType")
        .value("SETUP_NODE", NodeType::SETUP_NODE)
        .value("CoFHE_NODE", NodeType::CoFHE_NODE)
        .value("COMPUTE_NODE", NodeType::COMPUTE_NODE)
        .value("CLIENT_NODE", NodeType::CLIENT_NODE);

    py::class_<NodeDetails>(m, "NodeDetails")
        .def(py::init<>())
        .def(py::init<std::string, std::string, NodeType>())
        .def_readwrite("ip", &NodeDetails::ip,
                       R"pbdoc(
                Get the IP address of the node.
                Returns:
                    str: The IP address of the node.
            )pbdoc")
        .def_readwrite("port", &NodeDetails::port,
                       R"pbdoc(
                Get the port of the node.
                Returns:
                    str: The port of the node.
            )pbdoc")
        .def_readwrite("type", &NodeDetails::type,
                       R"pbdoc(
                Get the type of the node.
                Returns:
                    NodeType: The type of the node.
            )pbdoc");

    py::enum_<ReencryptorType>(m, "ReencryptorType")
        .value("RSA", ReencryptorType::RSA);

    py::class_<ReencryptorDetails>(m, "ReencryptorDetails")
        .def(py::init<>())
        .def(py::init<ReencryptorType, size_t>())
        .def_readwrite("type", &ReencryptorDetails::type,
                       R"pbdoc(
                Get the type of the reencryption.
                Returns:
                    ReencryptorType: The type of the reencryption.
            )pbdoc")
        .def_readwrite("key_size", &ReencryptorDetails::key_size,
                       R"pbdoc(
                Get the key size of the reencryption.
                Returns:
                    int: The key size of the reencryption.
            )pbdoc");

    py::enum_<CryptoSystemType>(m, "CryptoSystemType")
        .value("CoFHE_CPU", CryptoSystemType::CoFHE_CPU);

    py::class_<CryptoSystemDetails>(m, "CryptoSystemDetails")
        .def(py::init<>())
        .def(py::init([](CryptoSystemType type, py::bytes public_key,
                         size_t security_level, size_t k, size_t threshold,
                         size_t total_nodes, std::string N) {
            return CryptoSystemDetails(type, std::string(public_key),
                                       security_level, k, threshold,
                                       total_nodes, N);
        }))
        .def_readwrite("type", &CryptoSystemDetails::type,
                       R"pbdoc(
                Get the type of the cryptosystem.
                Returns:
                    CryptoSystemType: The type of the cryptosystem.
            )pbdoc")
        .def_property(
            "public_key",
            [](CryptoSystemDetails& self) {
                return py::bytes(self.public_key);
            },
            [](CryptoSystemDetails& self, py::bytes public_key) {
                self.public_key = std::string(public_key);
            },
            R"pbdoc(
                Get the public key of the cryptosystem.
                Returns:
                    bytes: The public key of the cryptosystem.
            )pbdoc")
        .def_readwrite("security_level", &CryptoSystemDetails::security_level,
                       R"pbdoc(
                               Get the security level of the cryptosystem.
                               
                               Returns:
                                      int: The security level of the cryptosystem.
                                 )pbdoc")
        .def_readwrite("k", &CryptoSystemDetails::k,
                       R"pbdoc(
                Get the k value of the cryptosystem.
                Returns:
                    int: The k value of the cryptosystem.
            )pbdoc")
        .def_readwrite("threshold", &CryptoSystemDetails::threshold,
                       R"pbdoc(
                 Get the threshold number of nodes.
                 Returns:
                      int: The threshold of the cryptosystem.
                )pbdoc")
        .def_readwrite("total_nodes", &CryptoSystemDetails::total_nodes,
                       R"pbdoc(
                               Get the total number of nodes.
                               Returns:
                                   int: The total number of nodes.
                                   )pbdoc")
        .def_readwrite("N", &CryptoSystemDetails::N,
                       R"pbdoc(
                Get the N value of the cryptosystem.
                Returns:
                    int: The N value of the cryptosystem.
            )pbdoc");

    py::class_<NetworkDetails>(m, "NetworkDetails")
        .def(py::init<>())
        .def(py::init([](NodeDetails self_node, std::vector<NodeDetails> nodes,
                         CryptoSystemDetails cryptosystem_details,
                         std::vector<py::bytes> secret_key_shares,
                         ReencryptorDetails reencryption_details) {
            std::vector<std::string> secret_key_shares_str;
            for (const auto& share : secret_key_shares) {
                secret_key_shares_str.push_back(std::string(share));
            }
            return NetworkDetails(self_node, nodes, cryptosystem_details,
                                  secret_key_shares_str, reencryption_details);
        }))
        .def_property_readonly(
            "self_node",
            py::overload_cast<>(&NetworkDetails::self_node, py::const_))
        .def_property_readonly(
            "nodes", py::overload_cast<>(&NetworkDetails::nodes, py::const_))
        .def_property_readonly(
            "cryptosystem_details",
            py::overload_cast<>(&NetworkDetails::cryptosystem_details,
                                py::const_))
        .def_property_readonly("secret_key_shares",
                               [](NetworkDetails& self) {
                                   std::vector<py::bytes> shares;
                                   for (const auto& share :
                                        self.secret_key_shares()) {
                                       shares.push_back(py::bytes(share));
                                   }
                                   return shares;
                               })
        .def_property_readonly(
            "reencryption_details",
            py::overload_cast<>(&NetworkDetails::reencryption_details,
                                py::const_))
        .def("to_string", &NetworkDetails::to_string)
        .def_static("from_string", &NetworkDetails::from_string);
}