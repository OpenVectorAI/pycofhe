#include <string>

#include <pybind11/functional.h>
#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

#include "cofhe.hpp"

using namespace CoFHE;
using namespace CoFHE::Network;

namespace py = pybind11;

void init_setup_request_response_bindings(py::module_& m) {
    py::enum_<SetupNodeResponse::Status>(m, "SetupNodeResponseStatus")
        .value("OK", SetupNodeResponse::Status::OK)
        .value("ERROR", SetupNodeResponse::Status::ERROR);

    py::class_<SetupNodeResponse>(m, "SetupNodeResponse")
        .def(py::init<>(
            [](SetupNodeResponse::Status status, const py::bytes& data) {
                return SetupNodeResponse(status, std::string(data));
            }))
        .def_property(
            "status",
            [](const SetupNodeResponse& self) { return self.status(); },
            [](SetupNodeResponse& self, SetupNodeResponse::Status status) {
                self.status() = status;
            })
        .def_property(
            "data_size",
            [](const SetupNodeResponse& self) { return self.data_size(); },
            [](SetupNodeResponse& self, size_t data_size) {
                self.data_size() = data_size;
            })
        .def_property(
            "data",
            [](const SetupNodeResponse& self) {
                return py::bytes(self.data());
            },
            [](SetupNodeResponse& self, const py::bytes& data) {
                self.data() = std::string(data);
            })
        .def("to_string",
             [](const SetupNodeResponse& self) {
                 return py::bytes(self.to_string());
             })
        .def_static("from_string", [](const py::bytes& str) {
            return SetupNodeResponse::from_string(std::string(str));
        });

    py::enum_<SetupNodeRequest::RequestType>(m, "SetupNodeRequestType")
        .value("BEAVERS_TRIPLET_REQUEST",
               SetupNodeRequest::RequestType::BEAVERS_TRIPLET_REQUEST)
        .value("COMPARISON_PAIR_REQUEST",
               SetupNodeRequest::RequestType::COMPARISION_PAIR_REQUEST)
        .value("JOIN_AS_NODE_REQUEST",
               SetupNodeRequest::RequestType::JOIN_AS_NODE_REQUEST)
        .value("NetworkDetailsRequest",
               SetupNodeRequest::RequestType::NetworkDetailsRequest);

    py::class_<SetupNodeRequest>(m, "SetupNodeRequest")
        .def(py::init<>(
            [](SetupNodeRequest::RequestType type, const py::bytes& data) {
                return SetupNodeRequest(type, std::string(data));
            }))
        .def_property(
            "type", [](const SetupNodeRequest& self) { return self.type(); },
            [](SetupNodeRequest& self, SetupNodeRequest::RequestType type) {
                self.type() = type;
            })
        .def_property(
            "data_size",
            [](const SetupNodeRequest& self) { return self.data_size(); },
            [](SetupNodeRequest& self, size_t data_size) {
                self.data_size() = data_size;
            })
        .def_property(
            "data",
            [](const SetupNodeRequest& self) { return py::bytes(self.data()); },
            [](SetupNodeRequest& self, const py::bytes& data) {
                self.data() = std::string(data);
            })
        .def("to_string",
             [](const SetupNodeRequest& self) {
                 return py::bytes(self.to_string());
             })
        .def_static("from_string", [](const py::bytes& str) {
            return SetupNodeRequest::from_string(std::string(str));
        });

    py::enum_<NetworkDetailsResponse::Status>(m, "NetworkDetailsResponseStatus")
        .value("OK", NetworkDetailsResponse::Status::OK)
        .value("ERROR", NetworkDetailsResponse::Status::ERROR);

    py::class_<NetworkDetailsResponse>(m, "NetworkDetailsResponse")
        .def(py::init<>(
            [](NetworkDetailsResponse::Status status, const py::bytes& data) {
                return NetworkDetailsResponse(status, std::string(data));
            }))
        .def_property(
            "status",
            [](const NetworkDetailsResponse& self) { return self.status(); },
            [](NetworkDetailsResponse& self,
               NetworkDetailsResponse::Status status) {
                self.status() = status;
            })
        .def_property(
            "data_size",
            [](const NetworkDetailsResponse& self) { return self.data_size(); },
            [](NetworkDetailsResponse& self, size_t data_size) {
                self.data_size() = data_size;
            })
        .def_property(
            "data",
            [](const NetworkDetailsResponse& self) {
                return py::bytes(self.data());
            },
            [](NetworkDetailsResponse& self, const py::bytes& data) {
                self.data() = std::string(data);
            })
        .def("to_string",
             [](const NetworkDetailsResponse& self) {
                 return py::bytes(self.to_string());
             })
        .def_static("from_string", [](const py::bytes& str) {
            return NetworkDetailsResponse::from_string(std::string(str));
        });

    py::enum_<NetworkDetailsRequest::RequestType>(m,
                                                  "NetworkDetailsRequestType")
        .value("GET", NetworkDetailsRequest::RequestType::GET)
        .value("SET", NetworkDetailsRequest::RequestType::SET);

    py::class_<NetworkDetailsRequest>(m, "NetworkDetailsRequest")
        .def(py::init<>(
            [](NetworkDetailsRequest::RequestType type, const py::bytes& data) {
                return NetworkDetailsRequest(type, std::string(data));
            }))
        .def_property(
            "type",
            [](const NetworkDetailsRequest& self) { return self.type(); },
            [](NetworkDetailsRequest& self,
               NetworkDetailsRequest::RequestType type) { self.type() = type; })
        .def_property(
            "data_size",
            [](const NetworkDetailsRequest& self) { return self.data_size(); },
            [](NetworkDetailsRequest& self, size_t data_size) {
                self.data_size() = data_size;
            })
        .def_property(
            "data",
            [](const NetworkDetailsRequest& self) {
                return py::bytes(self.data());
            },
            [](NetworkDetailsRequest& self, const py::bytes& data) {
                self.data() = std::string(data);
            })
        .def("to_string",
             [](const NetworkDetailsRequest& self) {
                 return py::bytes(self.to_string());
             })
        .def_static("from_string", [](const py::bytes& str) {
            return NetworkDetailsRequest::from_string(std::string(str));
        });
}