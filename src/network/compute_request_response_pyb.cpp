#include <string>

#include <pybind11/functional.h>
#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

#include "cofhe.hpp"

using namespace CoFHE;

namespace py = pybind11;

void init_compute_request_response_bindings(py::module_& m) {
    py::enum_<CoFHE::ComputeResponse::Status>(m, "ComputeResponseStatus")
        .value("OK", CoFHE::ComputeResponse::Status::OK)
        .value("ERROR", CoFHE::ComputeResponse::Status::ERROR);

    py::enum_<CoFHE::ComputeRequest::ComputeOperationType>(
        m, "ComputeOperationType")
        .value("UNARY", CoFHE::ComputeRequest::ComputeOperationType::UNARY)
        .value("BINARY", CoFHE::ComputeRequest::ComputeOperationType::BINARY)
        .value("TERNARY", CoFHE::ComputeRequest::ComputeOperationType::TERNARY);

    py::enum_<CoFHE::ComputeRequest::ComputeOperation>(m, "ComputeOperation")
        .value("DECRYPT", CoFHE::ComputeRequest::ComputeOperation::DECRYPT)
        .value("REENCRYPT", CoFHE::ComputeRequest::ComputeOperation::REENCRYPT)
        .value("ADD", CoFHE::ComputeRequest::ComputeOperation::ADD)
        .value("SUBTRACT", CoFHE::ComputeRequest::ComputeOperation::SUBTRACT)
        .value("MULTIPLY", CoFHE::ComputeRequest::ComputeOperation::MULTIPLY)
        .value("DIVIDE", CoFHE::ComputeRequest::ComputeOperation::DIVIDE)
        .value("LT", CoFHE::ComputeRequest::ComputeOperation::LT)
        .value("GT", CoFHE::ComputeRequest::ComputeOperation::GT)
        .value("EQ", CoFHE::ComputeRequest::ComputeOperation::EQ)
        .value("NEQ", CoFHE::ComputeRequest::ComputeOperation::NEQ)
        .value("LTEQ", CoFHE::ComputeRequest::ComputeOperation::LTEQ)
        .value("GTEQ", CoFHE::ComputeRequest::ComputeOperation::GTEQ);

    py::enum_<CoFHE::ComputeRequest::DataType>(m, "DataType")
        .value("SINGLE", CoFHE::ComputeRequest::DataType::SINGLE)
        .value("TENSOR", CoFHE::ComputeRequest::DataType::TENSOR)
        .value("TENSOR_ID", CoFHE::ComputeRequest::DataType::TENSOR_ID);

    py::enum_<CoFHE::ComputeRequest::DataEncrytionType>(m, "DataEncryptionType")
        .value("PLAINTEXT", CoFHE::ComputeRequest::DataEncrytionType::PLAINTEXT)
        .value("CIPHERTEXT",
               CoFHE::ComputeRequest::DataEncrytionType::CIPHERTEXT);

    py::class_<CoFHE::ComputeResponse>(m, "ComputeResponse")
        .def(py::init<CoFHE::ComputeResponse::Status, std::string>())
        .def_property(
            "status",
            [](const CoFHE::ComputeResponse& self) { return self.status(); },
            [](CoFHE::ComputeResponse& self,
               CoFHE::ComputeResponse::Status status) {
                self.status() = status;
            })
        .def_property(
            "data",
            [](const CoFHE::ComputeResponse& self) { return self.data(); },
            [](CoFHE::ComputeResponse& self, const std::string& data) {
                self.data() = data;
            })
        .def_property(
            "data_bytes",
            [](const CoFHE::ComputeResponse& self) {
                return py::bytes(self.data());
            },
            [](CoFHE::ComputeResponse& self, const py::bytes& data) {
                self.data() = std::string(data);
            })
        .def("to_string", &CoFHE::ComputeResponse::to_string)
        .def_static("from_string", &CoFHE::ComputeResponse::from_string);

    py::class_<CoFHE::ComputeRequest::ComputeOperationOperand>(
        m, "ComputeOperationOperand")
        .def(py::init<CoFHE::ComputeRequest::DataType,
                      CoFHE::ComputeRequest::DataEncrytionType, std::string>())
        .def(py::init<CoFHE::ComputeRequest::DataType,
                      CoFHE::ComputeRequest::DataEncrytionType, py::bytes>())
        .def_property(
            "data_type",
            [](const CoFHE::ComputeRequest::ComputeOperationOperand& self) {
                return self.data_type();
            },
            [](CoFHE::ComputeRequest::ComputeOperationOperand& self,
               CoFHE::ComputeRequest::DataType data_type) {
                self.data_type() = data_type;
            })
        .def_property(
            "encryption_type",
            [](const CoFHE::ComputeRequest::ComputeOperationOperand& self) {
                return self.encryption_type();
            },
            [](CoFHE::ComputeRequest::ComputeOperationOperand& self,
               CoFHE::ComputeRequest::DataEncrytionType encryption_type) {
                self.encryption_type() = encryption_type;
            })
        .def_property(
            "data",
            [](const CoFHE::ComputeRequest::ComputeOperationOperand& self) {
                return self.data();
            },
            [](CoFHE::ComputeRequest::ComputeOperationOperand& self,
               const std::string& data) { self.data() = data; })
        .def_property(
            "data_bytes",
            [](const CoFHE::ComputeRequest::ComputeOperationOperand& self) {
                return py::bytes(self.data());
            },
            [](CoFHE::ComputeRequest::ComputeOperationOperand& self,
               const py::bytes& data) { self.data() = std::string(data); })
        .def("to_string",
             &CoFHE::ComputeRequest::ComputeOperationOperand::to_string)
        .def_static(
            "from_string",
            py::overload_cast<const std::string&>(
                &CoFHE::ComputeRequest::ComputeOperationOperand::from_string))
        .def_static(
            "from_string",
            py::overload_cast<const std::string&, size_t>(
                &CoFHE::ComputeRequest::ComputeOperationOperand::from_string));

    py::class_<CoFHE::ComputeRequest::ComputeOperationInstance>(
        m, "ComputeOperationInstance")
        .def(py::init<const CoFHE::ComputeRequest::ComputeOperationType&,
                      const CoFHE::ComputeRequest::ComputeOperation&,
                      const std::vector<
                          CoFHE::ComputeRequest::ComputeOperationOperand>&>())
        .def_property(
            "operation_type",
            [](const CoFHE::ComputeRequest::ComputeOperationInstance& self) {
                return self.operation_type();
            },
            [](CoFHE::ComputeRequest::ComputeOperationInstance& self,
               CoFHE::ComputeRequest::ComputeOperationType operation_type) {
                self.operation_type() = operation_type;
            })
        .def_property(
            "operation",
            [](const CoFHE::ComputeRequest::ComputeOperationInstance& self) {
                return self.operation();
            },
            [](CoFHE::ComputeRequest::ComputeOperationInstance& self,
               CoFHE::ComputeRequest::ComputeOperation operation) {
                self.operation() = operation;
            })
        .def_property_readonly(
            "operands",
            [](const CoFHE::ComputeRequest::ComputeOperationInstance& self) {
                return self.operands();
            })
        .def("to_string",
             &CoFHE::ComputeRequest::ComputeOperationInstance::to_string)
        .def_static(
            "from_string",
            &CoFHE::ComputeRequest::ComputeOperationInstance::from_string);

    py::class_<CoFHE::ComputeRequest>(m, "ComputeRequest")
        .def(py::init<const CoFHE::ComputeRequest::ComputeOperationInstance&>())
        .def_property_readonly(
            "operation",
            [](const CoFHE::ComputeRequest& self) { return self.operation(); })
        .def("to_string", &CoFHE::ComputeRequest::to_string)
        .def_static("from_string", &CoFHE::ComputeRequest::from_string);
}