#include <string>

#include <pybind11/pybind11.h>

#include "cofhe.hpp"

using namespace CoFHE;
namespace py = pybind11;

void init_compute_request_response_bindings(py::module_& m);
void init_client_node_bindings(py::module_& m);
void init_binary_cpu_cryptosystem_bindings(py::module_& m);

PYBIND11_MODULE(network_core, m) {
    m.doc() = "Python binding for CoFHE networking";

    init_compute_request_response_bindings(m);
    init_client_node_bindings(m);
    init_binary_cpu_cryptosystem_bindings(m);
}