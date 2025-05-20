#include <string>

#include <pybind11/functional.h>
#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

#include "cofhe.hpp"

using namespace CoFHE;
using namespace CoFHE::Network;

namespace py = pybind11;

void init_request_response_bindings(py::module_& m) {
    py::enum_<ProtocolVersion>(m, "ProtocolVersion")
        .value("V1", ProtocolVersion::V1);

    py::enum_<ServiceType>(m, "ServiceType")
        .value("COMPUTE_REQUEST", ServiceType::COMPUTE_REQUEST)
        .value("COFHE_REQUEST", ServiceType::COFHE_REQUEST)
        .value("SETUP_REQUEST", ServiceType::SETUP_REQUEST);

    py::enum_<Response::Status>(m, "ResponseStatus")
        .value("OK", Response::Status::OK)
        .value("ERROR", Response::Status::ERROR);

    py::class_<Response::ResponseHeader>(m, "ResponseHeader")
        .def(py::init<ProtocolVersion, ServiceType, Response::Status, size_t>())
        .def_property(
            "protocol_version",
            [](Response::ResponseHeader& self) {
                return self.protocol_version();
            },
            [](Response::ResponseHeader& self, ProtocolVersion ver) {
                self.protocol_version() = ver;
            })
        .def_property(
            "type", [](Response::ResponseHeader& self) { return self.type(); },
            [](Response::ResponseHeader& self, ServiceType type) {
                self.type() = type;
            })
        .def_property(
            "status",
            [](Response::ResponseHeader& self) { return self.status(); },
            [](Response::ResponseHeader& self, Response::Status status) {
                self.status() = status;
            })
        .def_property(
            "data_size",
            [](Response::ResponseHeader& self) { return self.data_size(); },
            [](Response::ResponseHeader& self, size_t size) {
                self.data_size() = size;
            });

    py::class_<Response>(m, "Response")
        .def(py::init<>())
        .def(py::init<>([](ProtocolVersion proto_ver, ServiceType type,
                           Response::Status status, const py::bytes& data) {
            return Response(proto_ver, type, status, std::string(data));
        }))
        .def(py::init<>(
            [](Response::ResponseHeader header, const py::bytes& data) {
                return Response(header, std::string(data));
            }))
        .def_property(
            "header", [](Response& self) { return self.header(); },
            [](Response& self, Response::ResponseHeader header) {
                self.header() = header;
            })
        .def_property(
            "protocol_version",
            [](Response& self) { return self.protocol_version(); },
            [](Response& self, ProtocolVersion ver) {
                self.protocol_version() = ver;
            })
        .def_property(
            "type", [](Response& self) { return self.type(); },
            [](Response& self, ServiceType type) { self.type() = type; })
        .def_property(
            "status", [](Response& self) { return self.status(); },
            [](Response& self, Response::Status status) {
                self.status() = status;
            })
        .def_property(
            "data_size", [](Response& self) { return self.data_size(); },
            [](Response& self, size_t size) { self.data_size() = size; })
        .def_property(
            "data", [](Response& self) { return py::bytes(self.data()); },
            [](Response& self, const py::bytes& data) {
                self.data() = std::string(data);
            })
        .def("to_string",
             [](Response& self) { return py::bytes(self.to_string()); })
        .def("from_string", [](const py::bytes& str) {
            return Response::from_string(std::string(str));
        });

    py::class_<Request::RequestHeader>(m, "RequestHeader")
        .def(py::init<ProtocolVersion, ServiceType, size_t>())
        .def_property(
            "protocol_version",
            [](Request::RequestHeader& self) {
                return self.protocol_version();
            },
            [](Request::RequestHeader& self, ProtocolVersion ver) {
                self.protocol_version() = ver;
            })
        .def_property(
            "type", [](Request::RequestHeader& self) { return self.type(); },
            [](Request::RequestHeader& self, ServiceType type) {
                self.type() = type;
            })
        .def_property(
            "data_size",
            [](Request::RequestHeader& self) { return self.data_size(); },
            [](Request::RequestHeader& self, size_t size) {
                self.data_size() = size;
            });

    py::class_<Request>(m, "Request")
        .def(py::init<>([](ProtocolVersion proto_ver, ServiceType type,
                           const py::bytes& data) {
            return Request(proto_ver, type, std::string(data));
        }))
        .def(py::init<>(
            [](Request::RequestHeader header, const py::bytes& data) {
                return Request(header, std::string(data));
            }))
        .def_property(
            "header", [](Request& self) { return self.header(); },
            [](Request& self, Request::RequestHeader header) {
                self.header() = header;
            })
        .def_property(
            "protocol_version",
            [](Request& self) { return self.protocol_version(); },
            [](Request& self, ProtocolVersion ver) {
                self.protocol_version() = ver;
            })
        .def_property(
            "type", [](Request& self) { return self.type(); },
            [](Request& self, ServiceType type) { self.type() = type; })
        .def_property(
            "data_size", [](Request& self) { return self.data_size(); },
            [](Request& self, size_t size) { self.data_size() = size; })
        .def_property(
            "data", [](Request& self) { return py::bytes(self.data()); },
            [](Request& self, const py::bytes& data) {
                self.data() = std::string(data);
            })
        .def("to_string",
             [](Request& self) { return py::bytes(self.to_string()); })
        .def("from_string", [](const py::bytes& str) {
            return Request::from_string(std::string(str));
        });
}